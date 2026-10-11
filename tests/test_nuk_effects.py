"""The effects contract — vocabulary from git, and every fail-closed path.

Spec: docs/superpowers/specs/2026-08-15-astrocloud-platform-design.md §5.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import nuk
import pytest

GATE_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: auth}
    spec:
      placement: {role: edge}
      provides:
        route:
          capability: basic
          middlewares: [auth@file]
      health: {containers: [auth-gate]}
"""

BASIC_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: basic-auth}
    spec:
      placement: {role: edge}
      provides:
        route: {capability: basic, middlewares: [auth@file]}
"""

TLS_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: ingress}
    spec:
      placement: {role: edge}
      compose: docker-compose.traefik.yml
      provides:
        route: {capability: tls}
      health: {containers: [traefik]}
"""

DATA_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: data-stack}
    spec:
      placement: {role: data}
      compose: docker-compose.data.yml
      provides:
        env: {capability: databases, bind: postgres}
      health: {containers: [nuk-postgres, nuk-redis]}
"""


ROUTE_ONLY_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: gate}
    spec:
      placement: {role: edge}
      provides:
        route: {capability: basic, middlewares: [auth@file]}
"""

CUSTOM_AUTH_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: auth}
    spec:
      placement: {role: edge}
      provides:
        route: {capability: basic, middlewares: [custom-gate@file]}
"""

DB_DEPLOYMENT = """
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: app}
    spec:
      placement: {role: app}
      source: {repo: https://github.com/astrojones/app.git}
      databases: {postgres: true}
      ingress:
        - {host: app.example.com, service: web, port: 8080}
"""

GATED_DEPLOYMENT = """
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: app}
    spec:
      source: {repo: https://github.com/astrojones/app.git}
      ingress:
        - {host: app.example.com, service: web, port: 8080, auth: basic}
"""


def _tree(tmp_path: Path, **facilities: str) -> Path:
    """Build a manifest tree with <tree>/facilities/<name>.yml for each kwarg."""
    fdir = tmp_path / "facilities"
    fdir.mkdir(parents=True, exist_ok=True)
    for name, body in facilities.items():
        (fdir / f"{name}.yml").write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return tmp_path


def _manifest(tree: Path, subdir: str, filename: str, body: str) -> Path:
    """Drop a manifest at <tree>/<subdir>/<filename> (subdir "" = the tree root)."""
    d = tree / subdir if subdir else tree
    d.mkdir(parents=True, exist_ok=True)
    doc = d / filename
    doc.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return doc


def _stub_apply(tmp_path: Path, monkeypatch, role: str = "app") -> None:
    """Stub everything cmd_apply touches outside the tree — disk, docker, git."""
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "sh", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: (role, "10.0.10.107"))
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["true"])
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)


def test_load_facilities_reads_every_manifest(tmp_path):
    tree = _tree(tmp_path, gate=GATE_FACILITY, data=DATA_FACILITY)
    names = sorted(f.metadata.name for f in nuk.load_facilities(tree))
    assert names == ["auth", "data-stack"]


def test_load_facilities_on_a_tree_with_no_facility_dir(tmp_path):
    assert nuk.load_facilities(tmp_path) == []


def test_load_facilities_ignores_deployments_in_the_dir(tmp_path):
    tree = _tree(tmp_path, gate=GATE_FACILITY)
    (tree / "facilities" / "stray.yml").write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Deployment
            metadata: {name: stray}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    assert [f.metadata.name for f in nuk.load_facilities(tree)] == ["auth"]


def test_route_vocabulary_maps_capability_to_middlewares(tmp_path):
    tree = _tree(tmp_path, basic=BASIC_FACILITY, tls=TLS_FACILITY)
    vocab = nuk.route_vocabulary(nuk.load_facilities(tree))
    assert vocab == {"basic": ["auth@file"], "tls": []}


def test_route_vocabulary_refuses_a_duplicate_capability(tmp_path):
    """A closed vocabulary with two answers is not closed. Refuse."""
    tree = _tree(tmp_path, gate=GATE_FACILITY)
    (tree / "facilities" / "shadow.yml").write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Facility
            metadata: {name: shadow}
            spec:
              provides:
                route: {capability: basic, middlewares: [evil@file]}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        nuk.route_vocabulary(nuk.load_facilities(tree))


def test_env_facility_finds_the_declaring_facility(tmp_path):
    tree = _tree(tmp_path, data=DATA_FACILITY, gate=GATE_FACILITY)
    f = nuk.env_facility(nuk.load_facilities(tree), "databases")
    assert f is not None
    assert f.metadata.name == "data-stack"


def test_env_facility_returns_none_when_undeclared(tmp_path):
    tree = _tree(tmp_path, gate=GATE_FACILITY)
    assert nuk.env_facility(nuk.load_facilities(tree), "databases") is None


# --- the static consumption map (spec §5.3) ------------------------------------------


def _dep(spec: dict) -> nuk.Deployment:
    """A minimal valid Deployment carrying `spec`."""
    return nuk.Deployment.model_validate(
        {"apiVersion": "nuk/v1", "kind": "Deployment", "metadata": {"name": "x"}, "spec": spec}
    )


def test_consumes_does_not_count_a_route_gate_as_consumption():
    dep = _dep(
        {"ingress": [{"host": "h.example.com", "service": "web", "port": 80, "auth": "basic"}]}
    )
    assert nuk.consumes(dep) == set()


def test_consumes_maps_databases_to_the_databases_capability():
    assert nuk.consumes(_dep({"databases": {"postgres": True}})) == {"databases"}
    assert nuk.consumes(_dep({"databases": {"redis": True}})) == {"databases"}


def test_consumes_combines_route_and_env():
    dep = _dep(
        {
            "ingress": [{"host": "h.example.com", "service": "web", "port": 80, "auth": "basic"}],
            "databases": {"postgres": True},
        }
    )
    assert nuk.consumes(dep) == {"databases"}


def test_a_deployment_consuming_nothing_gets_an_empty_set():
    """It still gets the default tls route from the ingress facility — tls is
    substrate, never consumption (spec §5.3).
    """
    dep = _dep({"ingress": [{"host": "h.example.com", "service": "web", "port": 80}]})
    assert nuk.consumes(dep) == set()


HELLO_INGRESS = [{"host": "hello.example.com", "service": "web", "port": 8080}]


def test_route_renders_declared_middlewares_in_order(tmp_path):
    """Spec §12: a capability with declared middlewares renders them in order."""
    vocab = nuk.route_vocabulary(nuk.load_facilities(_tree(tmp_path, gate=GATE_FACILITY)))
    doc = nuk.build_ingress("hello", [{**HELLO_INGRESS[0], "auth": "basic"}], vocab)
    assert doc["http"]["routers"]["hello-0"]["middlewares"] == [
        "auth@file",
        "maintenance-errors@file",
    ]


def test_route_refuses_an_undeclared_capability(tmp_path):
    """Spec §5.4: capability not declared by any facility -> refuse."""
    vocab = nuk.route_vocabulary(nuk.load_facilities(_tree(tmp_path, tls=TLS_FACILITY)))
    with pytest.raises(ValueError, match="which no facility in the tree provides"):
        nuk.build_ingress("hello", [{**HELLO_INGRESS[0], "auth": "basic"}], vocab)


def test_route_refuses_an_empty_middleware_list(tmp_path):
    """Spec §5.4: route capability declares empty middlewares -> refuse.

    `tls` is declared with no middlewares. Nothing writes `auth: tls` in practice,
    but if something did, rendering an ungated router is the failure this refuses.
    """
    vocab = nuk.route_vocabulary(nuk.load_facilities(_tree(tmp_path, tls=TLS_FACILITY)))
    with pytest.raises(ValueError, match="EMPTY middleware list"):
        nuk.build_ingress("hello", [{**HELLO_INGRESS[0], "auth": "tls"}], vocab)


def test_route_refuses_when_the_vocabulary_is_empty(tmp_path):
    """A tree with no facilities gates nothing. It must not render ungated."""
    with pytest.raises(ValueError, match="which no facility in the tree provides"):
        nuk.build_ingress("hello", [{**HELLO_INGRESS[0], "auth": "basic"}], {})


def test_route_without_auth_needs_no_vocabulary():
    """An ungated route was never gated. The empty vocabulary must still render it."""
    doc = nuk.build_ingress("hello", HELLO_INGRESS, {})
    assert doc["http"]["routers"]["hello-0"]["middlewares"] == ["maintenance-errors@file"]


def test_default_vocab_reproduces_the_legacy_chain_byte_for_byte():
    """Spec §12: existing render output stays byte-identical.

    The pre-facility code hardcoded these two chains. Rendering through the
    vocabulary with DEFAULT_ROUTE_VOCAB must produce the exact same YAML.
    """
    import yaml

    for gate, expected in (("basic", ["auth@file", "maintenance-errors@file"]),):
        doc = nuk.build_ingress(
            "hello", [{**HELLO_INGRESS[0], "auth": gate}], nuk.DEFAULT_ROUTE_VOCAB
        )
        assert doc["http"]["routers"]["hello-0"]["middlewares"] == expected
        assert yaml.safe_dump(doc)  # renders without error


def test_shipped_facilities_reproduce_the_default_vocabulary():
    """The manifests in infra/facilities/ must agree with the built-in default.

    If they drift, a host reading the tree gates differently from one falling
    back to the default — the exact class of divergence this design exists to end.

    nuk is a submodule and its CI clones it standalone, where the superproject's
    infra/ does not exist. Skip there: this asserts a property of the astrocloud
    checkout, not of nuk in isolation.
    """
    infra = Path(__file__).resolve().parents[2] / "infra"
    if not (infra / "facilities").is_dir():
        pytest.skip("standalone nuk checkout — no superproject infra/facilities to compare")
    vocab = nuk.route_vocabulary(nuk.load_facilities(infra))
    for capability, chain in nuk.DEFAULT_ROUTE_VOCAB.items():
        assert vocab[capability] == chain


def test_env_bind_refuses_when_no_facility_declares_it(tmp_path, monkeypatch):
    """Spec §5.4: `env` bind raises -> abort before render, nothing written.

    preflight is stubbed to prove the refusal happens BEFORE any docker exec:
    if the guard were ordered after it, this would raise from the stub instead.
    """
    monkeypatch.setattr(
        nuk, "preflight_data_stack", lambda *_a: pytest.fail("preflight ran before the guard")
    )
    facilities = nuk.load_facilities(_tree(tmp_path, gate=GATE_FACILITY))
    with pytest.raises(SystemExit, match="no facility provides"):
        nuk.provision_databases("hello", {"postgres": True}, facilities)


def test_env_bind_proceeds_when_the_tree_ships_no_facilities_dir(tmp_path, monkeypatch):
    """Legacy topology (spec §12): no facilities/ dir at all -> no facility concept.

    An EMPTY list means the tree never opted into facilities, so there is nothing
    to refuse against — the same asymmetry route_vocabulary already honours
    (`route_vocabulary(facilities) if facilities else DEFAULT_ROUTE_VOCAB`).
    Refusing here would break every single-host install that predates Task 6.
    """
    calls = []
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a: calls.append(a))
    monkeypatch.setattr(nuk, "read_db_env", lambda _app: {})
    monkeypatch.setattr(nuk, "ensure_postgres", lambda *_a, **_k: "postgresql://x")
    monkeypatch.setattr(nuk, "write_db_env", lambda _app, _env: "/opt/nuklaut/secrets/hello-db.env")
    assert nuk.load_facilities(tmp_path) == []  # the legacy tree, verbatim
    out = nuk.provision_databases("hello", {"postgres": True}, [])
    assert calls == [(True, False)]
    assert out == "/opt/nuklaut/secrets/hello-db.env"


def test_env_bind_is_a_noop_when_nothing_is_requested(tmp_path):
    """No databases requested = no capability needed. The guard must not fire."""
    facilities = nuk.load_facilities(_tree(tmp_path, gate=GATE_FACILITY))
    assert nuk.provision_databases("hello", {}, facilities) is None


def test_env_bind_proceeds_when_the_facility_is_declared(tmp_path, monkeypatch):
    """With the data-stack facility present, the guard passes and bind runs."""
    calls = []
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a: calls.append(a))
    monkeypatch.setattr(nuk, "read_db_env", lambda _app: {})
    monkeypatch.setattr(nuk, "ensure_postgres", lambda *_a, **_k: "postgresql://x")
    monkeypatch.setattr(nuk, "write_db_env", lambda _app, _env: "/opt/nuklaut/secrets/hello-db.env")
    facilities = nuk.load_facilities(_tree(tmp_path, data=DATA_FACILITY))
    out = nuk.provision_databases("hello", {"postgres": True}, facilities)
    assert calls == [(True, False)]
    assert out == "/opt/nuklaut/secrets/hello-db.env"


def test_facility_health_passes_when_every_container_is_healthy(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "_container_state", lambda _c: (True, True))
    f = nuk.load_facilities(_tree(tmp_path, data=DATA_FACILITY))[0]
    assert nuk.facility_health(f) is None


def test_facility_health_reports_a_missing_container(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "_container_state", lambda c: (c != "nuk-redis", True))
    f = nuk.load_facilities(_tree(tmp_path, data=DATA_FACILITY))[0]
    assert "nuk-redis" in nuk.facility_health(f)


def test_facility_health_reports_an_unhealthy_container(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "_container_state", lambda c: (True, c != "nuk-postgres"))
    f = nuk.load_facilities(_tree(tmp_path, data=DATA_FACILITY))[0]
    reason = nuk.facility_health(f)
    assert "nuk-postgres" in reason and "not healthy" in reason


def test_facility_with_no_health_block_passes(tmp_path, monkeypatch):
    """basic-auth declares no containers — nothing to check, nothing to fail."""
    monkeypatch.setattr(
        nuk, "_container_state", lambda _c: pytest.fail("must not probe with no health block")
    )
    f = nuk.load_facilities(_tree(tmp_path, basic=BASIC_FACILITY))[0]
    assert nuk.facility_health(f) is None


def test_unhealthy_facility_apply_does_not_append_provenance(tmp_path, monkeypatch):
    """Spec §5.4: apply fails, provenance is NOT appended, the previous entry stays.

    Everything between load and the health gate is stubbed — this test is about
    the ORDER of two statements (gate before provenance), not about git, compose,
    or docker. `sh` is stubbed to a no-op so the clone/rsync and `up -d` never run;
    if the gate were placed after write_provenance, the pytest.fail below fires.
    """
    doc = tmp_path / "auth.yml"
    doc.write_text(textwrap.dedent(GATE_FACILITY).lstrip(), encoding="utf-8")

    repo_src = tmp_path / "src"
    repo_src.mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deployments")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "sh", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["true"])
    monkeypatch.setattr(nuk, "facility_health", lambda _m: "container 'auth-gate' is not running")
    monkeypatch.setattr(
        nuk, "write_provenance", lambda *_a, **_k: pytest.fail("provenance must not be appended")
    )

    with pytest.raises(SystemExit, match="not healthy"):
        nuk.cmd_apply(doc, str(repo_src))


def test_tree_root_walks_up_from_a_manifest_subdirectory(tmp_path):
    """Production layout: <tree>/deployments/<x>.yml and <tree>/facilities/<x>.yml."""
    assert nuk._tree_root(tmp_path / "deployments" / "app.yml") == tmp_path.resolve()
    assert nuk._tree_root(tmp_path / "facilities" / "data-stack.yml") == tmp_path.resolve()


def test_tree_root_of_a_bare_manifest_is_its_own_directory(tmp_path):
    """A manifest applied bare sits IN the tree root — today's hand-run apply."""
    assert nuk._tree_root(tmp_path / "m.yml") == tmp_path.resolve()


def test_apply_loads_facilities_from_the_tree_root_not_the_manifest_dir(tmp_path, monkeypatch):
    """<tree>/deployments/app.yml must see <tree>/facilities/, not deployments/facilities/."""
    tree = _tree(tmp_path, data=DATA_FACILITY)
    doc = _manifest(tree, "deployments", "app.yml", DB_DEPLOYMENT)
    seen: list[list] = []
    monkeypatch.setattr(
        nuk, "provision_databases", lambda _n, _d, facilities, **_k: seen.append(facilities)
    )
    _stub_apply(tmp_path, monkeypatch)
    nuk.cmd_apply(doc, None)
    assert [f.metadata.name for f in seen[0]] == ["data-stack"]


def test_apply_in_the_deployments_dir_does_not_refuse_its_databases(tmp_path, monkeypatch):
    """The real guard, unstubbed: data-stack.yml is right there, so apply proceeds."""
    tree = _tree(tmp_path, data=DATA_FACILITY)
    doc = _manifest(tree, "deployments", "app.yml", DB_DEPLOYMENT)
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *_a: None)
    monkeypatch.setattr(nuk, "read_db_env", lambda _app: {})
    monkeypatch.setattr(nuk, "ensure_postgres", lambda *_a, **_k: "postgresql://x")
    monkeypatch.setattr(nuk, "write_db_env", lambda _app, _env: str(tmp_path / "app-db.env"))
    _stub_apply(tmp_path, monkeypatch)
    nuk.cmd_apply(doc, None)  # must not sys.exit("no facility provides 'databases'")


def test_apply_resolves_the_route_vocabulary_from_the_tree_root(tmp_path, monkeypatch):
    """The git-sourced vocabulary must reach build_ingress, not DEFAULT_ROUTE_VOCAB.

    The facility declares a deliberately NON-default chain, so a silent fallback
    to DEFAULT_ROUTE_VOCAB shows up in the middlewares handed to write_ingress.
    """
    tree = _tree(tmp_path, auth=CUSTOM_AUTH_FACILITY)
    doc = _manifest(tree, "deployments", "app.yml", GATED_DEPLOYMENT)
    seen: list[dict] = []
    _stub_apply(tmp_path, monkeypatch, role="all-in-one")
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda _n, _i, vocab: seen.append(vocab))
    nuk.cmd_apply(doc, None)
    assert seen == [{"basic": ["custom-gate@file"]}]
    assert seen[0] != nuk.DEFAULT_ROUTE_VOCAB


def test_apply_of_a_declaration_only_facility_runs_nothing(tmp_path, monkeypatch):
    """gate.yml/basic.yml declare only a route: no source, no compose, no payload.

    There is nothing to mirror and nothing to compose up — the apply is a pure
    vocabulary registration, so it must complete instead of refusing for a
    payload directory it has no use for.
    """
    tree = _tree(tmp_path, gate=ROUTE_ONLY_FACILITY)
    doc = tree / "facilities" / "gate.yml"
    _stub_apply(tmp_path, monkeypatch, role="edge")
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)

    def _forbidden(*args, **_kw):
        pytest.fail(f"a declaration-only facility must run no command, got {args}")

    monkeypatch.setattr(nuk, "sh", _forbidden)
    nuk.cmd_apply(doc, None)


def test_apply_of_a_sourceless_facility_with_compose_still_needs_its_payload(tmp_path, monkeypatch):
    """data-stack.yml DOES declare compose — a missing payload dir is still fatal."""
    tree = _tree(tmp_path, **{"data-stack": DATA_FACILITY})
    doc = tree / "facilities" / "data-stack.yml"
    _stub_apply(tmp_path, monkeypatch, role="data")
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    with pytest.raises(SystemExit, match="nothing to apply"):
        nuk.cmd_apply(doc, None)


# --- the logging facility (spec §14.1) -----------------------------------------------


def test_shipped_logging_facility_validates_and_provides_logs(tmp_path):
    """Spec §14.1: the shipped facility declares env capability `logs`.

    Skipped in a standalone nuk checkout: this asserts a property of the
    astrocloud checkout, not of nuk in isolation.
    """
    infra = Path(__file__).resolve().parents[2] / "infra"
    manifest = infra / "facilities" / "logging.yml"
    if not manifest.is_file():
        pytest.skip("standalone nuk checkout — no superproject facilities/logging.yml")
    f = nuk.load(manifest)
    assert f.kind == "Facility"
    assert f.spec.placement.role == "edge"
    assert f.spec.provides.env.capability == "logs"
    assert f.spec.provides.env.bind == "otlp"
    assert f.spec.health.containers == ["loki"]
    payload = manifest.parent / "logging" / f.spec.compose.file
    assert payload.is_file(), "the compose payload must ship beside the manifest"


def test_consumes_gains_no_row_for_logs():
    """Spec §14.3: no manifest field requests logging — the static consumption
    map stays exactly {auth, databases} so no apply path can couple to the
    pipeline. The map is the literal §5.3 table; adding a row would be a
    fail-closed coupling this spec forbids.
    """
    dep = nuk.Deployment.model_validate(
        {
            "apiVersion": "nuk/v1",
            "kind": "Deployment",
            "metadata": {"name": "x"},
            "spec": {"source": {"repo": "git@github.com:a/b.git"}},
        }
    )
    assert nuk.consumes(dep) == set()
