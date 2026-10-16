"""Wire records: round-trips and goldens for exact key sets, key order and absent-vs-null."""

from __future__ import annotations

import json

import nuk
import pytest
from nuk import (
    AppFeatures,
    AppIngress,
    AppOverview,
    AppSource,
    ComposeImage,
    ComposeOverride,
    ConvergeStatus,
    LoggingStatus,
    ManifestResult,
    Overview,
    RedirectRegex,
    ReleaseEntry,
    RouterStatus,
    ServiceWiring,
    SollVsIst,
    SourceBlock,
    StripPrefix,
    TraefikConfig,
    TraefikRouter,
    TraefikService,
    Workflow,
)

# --- compose override ----------------------------------------------------------


def test_service_wiring_networks_always_present_rest_only_when_non_empty():
    bare = ServiceWiring(networks=[]).to_wire()
    assert bare == {"networks": []}
    full = ServiceWiring(["edge"], ["10.0.0.1:80:8080"], ["/s/a.env"]).to_wire()
    assert list(full) == ["networks", "ports", "env_file"]
    assert full == {"networks": ["edge"], "ports": ["10.0.0.1:80:8080"], "env_file": ["/s/a.env"]}


def test_compose_override_golden_and_networks_present_even_when_empty():
    doc = ComposeOverride(
        {"web": ServiceWiring(["edge", "data"], env_file=["/s/a.env"])}, ["edge", "data"]
    ).to_wire()
    assert list(doc) == ["services", "networks"]
    assert doc == {
        "services": {"web": {"networks": ["edge", "data"], "env_file": ["/s/a.env"]}},
        "networks": {"edge": {"external": True}, "data": {"external": True}},
    }
    assert ComposeOverride({"w": ServiceWiring([])}, []).to_wire()["networks"] == {}


# --- traefik -------------------------------------------------------------------


def test_traefik_router_golden_full_and_minimal():
    full = TraefikRouter(
        "Host(`a.example`)", ["websecure"], "app-0", "letsencrypt", ["auth@file"], 10
    ).to_wire()
    assert list(full) == ["rule", "entryPoints", "service", "tls", "middlewares", "priority"]
    assert full["tls"] == {"certResolver": "letsencrypt"}
    minimal = TraefikRouter("Host(`a.example`)", ["mesh"], "app-0").to_wire()
    assert list(minimal) == ["rule", "entryPoints", "service"]


def test_traefik_router_priority_zero_is_kept_but_none_is_omitted():
    assert TraefikRouter("r", ["e"], "s", priority=0).to_wire()["priority"] == 0
    assert "priority" not in TraefikRouter("r", ["e"], "s", priority=None).to_wire()


def test_traefik_service_and_middlewares_golden():
    assert TraefikService("http://app-web-1:80").to_wire() == {
        "loadBalancer": {"servers": [{"url": "http://app-web-1:80"}]}
    }
    assert StripPrefix(["/api"]).to_wire() == {"stripPrefix": {"prefixes": ["/api"]}}
    redirect = RedirectRegex(r"^https?://www\.a/(.*)", "https://a/${1}", True).to_wire()
    assert list(redirect["redirectRegex"]) == ["regex", "replacement", "permanent"]
    assert redirect["redirectRegex"]["permanent"] is True


def test_traefik_config_omits_middlewares_when_empty_and_nests_under_http():
    routers = {"app-0": TraefikRouter("r", ["websecure"], "app-0")}
    services = {"app-0": TraefikService("http://x:1")}
    bare = TraefikConfig(routers, services).to_wire()
    assert list(bare) == ["http"]
    assert list(bare["http"]) == ["routers", "services"]
    with_mw = TraefikConfig(routers, services, {"app-0-strip": StripPrefix(["/a"])}).to_wire()
    assert list(with_mw["http"]) == ["routers", "services", "middlewares"]


# --- converge status -----------------------------------------------------------


def _block() -> SourceBlock:
    return SourceBlock(
        "ok",
        None,
        "v1",
        "abc",
        ["manifests", "routes"],
        [ManifestResult("web", "Deployment"), ManifestResult("pg", "Database", "failed", "boom")],
        ["a.example"],
        ["b.example"],
    )


def _status(**kw: object) -> ConvergeStatus:
    base = {
        "role": "edge",
        "tenant": None,
        "applied_at": "2026-01-01T00:00:00Z",
        "reap_warnings": ["w"],
        "sources": {"platform": _block()},
    }
    return ConvergeStatus(**{**base, **kw})


def test_manifest_result_golden_has_all_four_keys_with_explicit_null_error():
    wire = ManifestResult("web", "Deployment").to_wire()
    assert list(wire) == ["name", "kind", "result", "error"]
    assert wire["error"] is None


def test_source_block_golden_key_order():
    assert list(_block().to_wire()) == [
        "result",
        "error",
        "tag",
        "commit",
        "apply",
        "manifests",
        "rendered",
        "refusedRoutes",
    ]


def test_converge_status_logging_and_error_are_absent_not_null():
    wire = _status().to_wire()
    assert list(wire) == ["role", "tenant", "appliedAt", "reapWarnings", "sources"]
    full = _status(logging=LoggingStatus(True, "ok"), error="x").to_wire()
    assert list(full) == [*wire, "logging", "error"]
    assert full["logging"] == {"healthy": True, "detail": "ok"}


def test_converge_status_json_is_byte_stable():
    text = json.dumps(_status().to_wire(), indent=2) + "\n"
    assert text.startswith('{\n  "role": "edge",\n  "tenant": null,\n  "appliedAt"')


@pytest.mark.parametrize(
    "record",
    [
        ManifestResult("web", "Deployment"),
        ManifestResult("pg", "Database", "refused", "why"),
        LoggingStatus(False, "down"),
        _block(),
        SourceBlock(),
        _status(),
        _status(tenant="acme", logging=LoggingStatus(True, "ok"), error="e"),
    ],
)
def test_converge_records_round_trip(record):
    assert type(record).from_wire(record.to_wire()) == record


def test_converge_status_survives_a_json_round_trip():
    status = _status(logging=LoggingStatus(False, "d"))
    assert ConvergeStatus.from_wire(json.loads(json.dumps(status.to_wire()))) == status


@pytest.mark.parametrize(
    ("cls", "bad"),
    [
        (ManifestResult, {"name": "x", "kind": "Nope", "result": "ok", "error": None}),
        (ManifestResult, {"name": 1, "kind": "Facility", "result": "ok", "error": None}),
        (ManifestResult, []),
        (LoggingStatus, {"healthy": "yes", "detail": "d"}),
        (SourceBlock, {"result": "weird"}),
        (SourceBlock, {"result": "ok", "manifests": [{"name": "x"}]}),
        (ConvergeStatus, []),
        (ConvergeStatus, {"role": "edge", "sources": []}),
        (ConvergeStatus, {"role": "edge", "sources": {"p": {"result": "weird"}}}),
    ],
)
def test_converge_from_wire_is_none_for_non_conforming_shapes(cls, bad):
    assert cls.from_wire(bad) is None


def test_converge_status_tolerates_a_bad_logging_block():
    wire = _status().to_wire() | {"logging": "garbage"}
    assert ConvergeStatus.from_wire(wire).logging is None


# --- provenance / docker -------------------------------------------------------


def test_release_entry_golden_key_order_and_round_trip():
    e = ReleaseEntry("r", "main", "c" * 40, "sha256:d", "2026-01-01T00:00:00Z")
    assert list(e.to_wire()) == ["repo", "branch", "commit", "imageDigest", "appliedAt"]
    assert ReleaseEntry.from_wire(e.to_wire()) == e
    empty = ReleaseEntry()
    assert ReleaseEntry.from_wire(empty.to_wire()) == empty
    assert list(empty.to_wire()) == list(e.to_wire())


def test_release_entry_from_wire_is_tolerant():
    legacy = ReleaseEntry.from_wire({"commit": "abc", "repo": 5, "imageDigest": ["x"]})
    assert legacy == ReleaseEntry(commit="abc")


def test_release_entry_same_release_ignores_the_timestamp():
    a = ReleaseEntry("r", "main", "c", "d", "t1")
    assert a.same_release(ReleaseEntry("r", "main", "c", "d", "t2"))
    assert not a.same_release(ReleaseEntry("r", "main", "c2", "d", "t1"))
    assert not a.same_release(ReleaseEntry("r", "main", "c", None, "t1"))


def test_compose_image_reads_docker_pascal_case_and_degrades():
    assert ComposeImage.from_wire({"Repository": "img", "Tag": "1"}) == ComposeImage("img", "1")
    assert ComposeImage.from_wire({"Repository": 1}) == ComposeImage(None, None)


# --- overview ------------------------------------------------------------------


def test_app_source_round_trip_and_tolerance():
    s = AppSource("o/r", None)
    assert list(s.to_wire()) == ["repo", "branch"]
    assert s.to_wire()["branch"] is None
    assert AppSource.from_wire(s.to_wire()) == s
    assert AppSource.from_wire("nonsense") == AppSource()
    assert AppSource.from_wire({"repo": 3, "branch": "b"}) == AppSource(None, "b")


def test_app_ingress_golden_round_trip_and_tolerance():
    i = AppIngress("a.example", "web", 80, "/p", "basic")
    assert list(i.to_wire()) == ["host", "service", "port", "path", "auth"]
    assert AppIngress.from_wire(i.to_wire()) == i
    bare = AppIngress("a.example")
    assert bare.to_wire() == {
        "host": "a.example",
        "service": None,
        "port": None,
        "path": None,
        "auth": None,
    }
    assert AppIngress.from_wire(bare.to_wire()) == bare
    assert AppIngress.from_wire({"host": "h", "port": True}) == AppIngress("h")
    assert AppIngress.from_wire({"host": ""}) is None
    assert AppIngress.from_wire({"service": "web"}) is None
    assert AppIngress.from_wire("x") is None


def test_app_features_golden_and_declared_databases_reading():
    assert list(AppFeatures().to_wire()) == ["postgres", "redis", "postgresDriver"]
    assert AppFeatures.from_databases({"postgres": {"driver": "asyncpg"}, "redis": True}) == (
        AppFeatures(True, True, "asyncpg")
    )
    assert AppFeatures.from_databases({"postgres": True}) == AppFeatures(True, False, None)
    assert AppFeatures.from_databases({"postgres": {}}) == AppFeatures()
    assert AppFeatures.from_databases(None) == AppFeatures()
    assert AppFeatures.from_databases({"postgres": {"driver": 3}}) == AppFeatures(True, False, None)


def test_workflow_and_router_status_golden():
    assert list(Workflow("ci.yml", "CI", ["push"]).to_wire()) == ["file", "name", "triggers"]
    wire = RouterStatus("app-0", "Host(`a`)").to_wire()
    assert list(wire) == ["id", "rule", "live"]
    assert wire["live"] is None


def test_soll_vs_ist_golden():
    wire = SollVsIst(3, 1, None, 4).to_wire()
    assert list(wire) == ["declaredHosts", "observedHosts", "declaredApps", "observedApps"]
    assert wire["declaredApps"] is None


def _app(**kw: object) -> AppOverview:
    base = {
        "name": "web",
        "hosts": ["a.example"],
        "source": None,
        "repo_url": None,
        "commit": None,
        "commit_url": None,
        "last_commit": None,
        "version": None,
        "routers": [],
        "drift": "unknown",
        "features": AppFeatures(),
        "workflows": [],
        "ingress": [],
        "notes": [],
        "image_digest": None,
    }
    return AppOverview(**{**base, **kw})


def test_app_overview_golden_key_order_and_null_not_omitted():
    wire = _app().to_wire()
    assert list(wire) == [
        "name",
        "hosts",
        "source",
        "repoUrl",
        "commit",
        "commitUrl",
        "lastCommit",
        "version",
        "routers",
        "drift",
        "features",
        "workflows",
        "ingress",
        "notes",
        "imageDigest",
    ]
    assert wire["source"] is None
    assert wire["imageDigest"] is None
    nested = _app(
        source=AppSource("o/r", "main"),
        routers=[RouterStatus("web-0", "r", "enabled")],
        workflows=[Workflow("ci.yml", "CI", ["push"])],
        ingress=[AppIngress("a.example")],
    ).to_wire()
    assert nested["source"] == {"repo": "o/r", "branch": "main"}
    assert nested["routers"] == [{"id": "web-0", "rule": "r", "live": "enabled"}]


def test_overview_golden_optional_blocks_absent_then_ordered():
    base = Overview([_app()], False, "/opt/nuklaut", "2026-01-01T00:00:00Z", [])
    wire = base.to_wire()
    assert list(wire) == ["apps", "liveRoutingAvailable", "nukRoot", "generatedAt", "errors"]
    host = nuk.Host.model_validate(
        {"name": "h", "provider": "manual", "role": "edge", "privateIp": "10.0.0.1"}
    )
    full = Overview(
        base.apps,
        False,
        base.nuk_root,
        base.generated_at,
        [],
        converge=_status(),
        hosts=[host],
        soll_vs_ist=SollVsIst(1, 1, None, 1),
    ).to_wire()
    assert list(full) == [*wire, "converge", "hosts", "sollVsIst"]
    assert full["hosts"] == [host.model_dump(by_alias=True)]
    assert json.dumps(full)  # everything in it is JSON-serialisable


def test_overview_empty_hosts_list_is_present_not_absent():
    wire = Overview([], False, "/r", "t", [], hosts=[]).to_wire()
    assert wire["hosts"] == []


# --- Databases helpers ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "pg", "redis", "driver"),
    [
        ({}, False, False, None),
        ({"postgres": True}, True, False, None),
        ({"postgres": {}}, False, False, None),
        ({"postgres": {"driver": "asyncpg"}, "redis": True}, True, True, "asyncpg"),
        ({"redis": True}, False, True, None),
    ],
)
def test_databases_helpers_keep_the_raw_dict_truthiness(raw, pg, redis, driver):
    dbs = nuk.Databases.model_validate(raw)
    assert (dbs.wants_postgres, dbs.wants_redis, dbs.postgres_driver) == (pg, redis, driver)
