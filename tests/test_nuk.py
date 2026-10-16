"""Unit tests for nuk's pure render functions (build_ingress / build_override).

These need only pyyaml — no /opt/nuklaut, no docker, no controller.

    uv run pytest
"""

from __future__ import annotations

import subprocess

import nuk
import pytest
import yaml

# --- regression: legacy {host,service,port} must render exactly as before -----


def test_legacy_single_host_gets_maintenance_only():
    """The shape the two live apps (bartix.de, pd.jonaheidsick.de) ship today.

    Every router now inherits the controller-wide maintenance-errors middleware,
    but it is a cross-file (@file) reference — NOT an app-local middleware
    definition — so http.middlewares stays empty when nothing strips/redirects.
    """
    doc = nuk.build_ingress(
        "bartix", [{"host": "bartix.de", "service": "web", "port": 8080}], nuk.DEFAULT_ROUTE_VOCAB
    )
    assert doc == {
        "http": {
            "routers": {
                "bartix-0": {
                    "rule": "Host(`bartix.de`)",
                    "entryPoints": ["websecure"],
                    "service": "bartix-0",
                    "tls": {"certResolver": "letsencrypt"},
                    "middlewares": ["maintenance-errors@file"],
                }
            },
            "services": {
                "bartix-0": {"loadBalancer": {"servers": [{"url": "http://bartix-web-1:8080"}]}}
            },
        }
    }
    # No app-LOCAL middleware definitions (maintenance-errors lives in global.yml).
    assert "middlewares" not in doc["http"]


def test_empty_ingress_is_none():
    assert nuk.build_ingress("x", [], nuk.DEFAULT_ROUTE_VOCAB) is None
    assert nuk.build_ingress("x", None, nuk.DEFAULT_ROUTE_VOCAB) is None


# --- kolbe: same-origin two-image split via PathPrefix + stripPrefix ----------


def test_kolbe_pathprefix_split():
    doc = nuk.build_ingress(
        "kolbe",
        [
            {
                "host": "kolbe.astrojones.de",
                "path": "/api",
                "stripPrefix": True,
                "service": "backend",
                "port": 8000,
            },
            {"host": "kolbe.astrojones.de", "service": "frontend", "port": 80},
        ],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    routers = doc["http"]["routers"]
    services = doc["http"]["services"]
    mws = doc["http"]["middlewares"]

    # /api router: Host && PathPrefix, strip middleware attached, points at backend
    assert routers["kolbe-0"]["rule"] == "Host(`kolbe.astrojones.de`) && PathPrefix(`/api`)"
    # strip middleware first, then the inherited maintenance-errors reference
    assert routers["kolbe-0"]["middlewares"] == [
        "kolbe-0-strip",
        "maintenance-errors@file",
    ]
    assert mws["kolbe-0-strip"] == {"stripPrefix": {"prefixes": ["/api"]}}
    assert services["kolbe-0"]["loadBalancer"]["servers"][0]["url"] == "http://kolbe-backend-1:8000"

    # catch-all frontend router: plain Host, only the inherited maintenance mw
    assert routers["kolbe-1"]["rule"] == "Host(`kolbe.astrojones.de`)"
    assert routers["kolbe-1"]["middlewares"] == ["maintenance-errors@file"]
    assert services["kolbe-1"]["loadBalancer"]["servers"][0]["url"] == "http://kolbe-frontend-1:80"


def test_path_without_strip_has_no_local_middleware():
    """PathPrefix without stripPrefix defines no app-local middleware; the router
    still inherits the maintenance-errors reference.
    """
    doc = nuk.build_ingress(
        "a", [{"host": "h", "path": "/x", "service": "s", "port": 1}], nuk.DEFAULT_ROUTE_VOCAB
    )
    assert doc["http"]["routers"]["a-0"]["rule"] == "Host(`h`) && PathPrefix(`/x`)"
    assert doc["http"]["routers"]["a-0"]["middlewares"] == ["maintenance-errors@file"]
    # no app-local middleware DEFINITIONS (maintenance-errors lives in global.yml)
    assert "middlewares" not in doc["http"]


def test_every_app_router_inherits_maintenance_errors():
    """The www-redirect router is the one exception — it 301s, no backend to guard."""
    doc = nuk.build_ingress(
        "kolbeapp",
        [{"host": "kolbeapp.de", "service": "frontend", "port": 80, "www": True}],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    routers = doc["http"]["routers"]
    assert routers["kolbeapp-0"]["middlewares"] == ["maintenance-errors@file"]
    assert routers["kolbeapp-0-www"]["middlewares"] == ["kolbeapp-0-www-redirect"]


def test_auth_basic_prepends_the_gate_ahead_of_maintenance_errors():
    """auth: basic resolves through the route capability `basic` (auth@file). The reference is
    cross-file (@file), so no app-local middleware definitions are emitted.
    """
    doc = nuk.build_ingress(
        "nukview",
        [{"host": "nuk.example.de", "service": "nukview", "port": 3000, "auth": "basic"}],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    assert doc["http"]["routers"]["nukview-0"]["middlewares"] == [
        "auth@file",
        "maintenance-errors@file",
    ]
    assert "middlewares" not in doc["http"]


def test_auth_basic_with_pathprefix_orders_basic_then_strip():
    """When a path is stripped too, the gate stays outermost, then strip, then maintenance."""
    doc = nuk.build_ingress(
        "api",
        [
            {
                "host": "h",
                "path": "/api",
                "stripPrefix": True,
                "service": "s",
                "port": 1,
                "auth": "basic",
            }
        ],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    assert doc["http"]["routers"]["api-0"]["middlewares"] == [
        "auth@file",
        "api-0-strip",
        "maintenance-errors@file",
    ]


def test_default_route_vocab_is_basic_only():
    assert nuk.DEFAULT_ROUTE_VOCAB == {"basic": ["auth@file"]}


@pytest.mark.parametrize("bad", ["authentik", "oauth2-proxy", "oauth", "Oauth", "sso"])
def test_unknown_auth_value_refuses_to_render_instead_of_publishing(bad):
    """An unrecognised `auth` must ABORT, never render an ungated router.

    Regression for a fail-open authentication control: `auth` was an unvalidated `str` and
    the render matched it with if/elif and no else, so a typo produced a router with no auth
    middleware and no error. build_ingress works on raw dicts (it does not see the Literal),
    so it refuses on its own.
    """
    with pytest.raises(ValueError, match="no facility in the tree provides"):
        nuk.build_ingress(
            "demo", [{"host": "h", "service": "s", "port": 1, "auth": bad}], nuk.DEFAULT_ROUTE_VOCAB
        )


@pytest.mark.parametrize("retired", ["oauth", "authentik", "oauth2-proxy"])
def test_ingress_auth_rejects_the_retired_gates_at_load(retired):
    """The retired gates are a load-time ValidationError (fail closed), not a silent no-op."""
    with pytest.raises(ValueError):
        nuk.Ingress(host="h", service="s", port=1, auth=retired)


def test_ingress_auth_accepts_only_basic():
    assert nuk.Ingress(host="h", service="s", port=1, auth="basic").auth == "basic"
    assert nuk.Ingress(host="h", service="s", port=1).auth is None


def test_explicit_priority():
    doc = nuk.build_ingress(
        "a", [{"host": "h", "service": "s", "port": 1, "priority": 100}], nuk.DEFAULT_ROUTE_VOCAB
    )
    assert doc["http"]["routers"]["a-0"]["priority"] == 100


# --- address: remote backend (e.g. a libvirt VM on another host) --------------


def test_address_backend_bypasses_local_container_naming():
    doc = nuk.build_ingress(
        "hello",
        [{"host": "hello.astrojones.guru", "address": "10.10.2.4:8080"}],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    servers = doc["http"]["services"]["hello-0"]["loadBalancer"]["servers"]
    assert servers == [{"url": "http://10.10.2.4:8080"}]


def test_ingress_model_requires_address_xor_service_port():
    # local backend: service + port, no address — fine.
    nuk.Ingress(host="h", service="s", port=1)
    # remote backend: address only — fine.
    nuk.Ingress(host="h", address="10.10.2.4:8080")
    # neither given.
    with pytest.raises(ValueError, match=r"service.*port.*required"):
        nuk.Ingress(host="h")
    # both given — ambiguous, rejected.
    with pytest.raises(ValueError, match="set either"):
        nuk.Ingress(host="h", service="s", port=1, address="10.10.2.4:8080")


# --- www redirect (opt-in, apex domains) --------------------------------------


def test_www_redirect_router_and_middleware():
    doc = nuk.build_ingress(
        "kolbeapp",
        [
            {"host": "kolbeapp.de", "service": "frontend", "port": 80, "www": True},
        ],
        nuk.DEFAULT_ROUTE_VOCAB,
    )
    routers = doc["http"]["routers"]
    mws = doc["http"]["middlewares"]
    # main router unchanged
    assert routers["kolbeapp-0"]["rule"] == "Host(`kolbeapp.de`)"
    # extra www router with a permanent 301 redirect middleware
    assert routers["kolbeapp-0-www"]["rule"] == "Host(`www.kolbeapp.de`)"
    assert routers["kolbeapp-0-www"]["middlewares"] == ["kolbeapp-0-www-redirect"]
    rr = mws["kolbeapp-0-www-redirect"]["redirectRegex"]
    assert rr["regex"] == r"^https?://www\.kolbeapp\.de/(.*)"
    assert rr["replacement"] == "https://kolbeapp.de/${1}"
    assert rr["permanent"] is True


def _override(name, ingress, *args, **kwargs):
    """Wire form of build_override for dict ingress entries; the no-wiring None is a test bug."""
    parsed = [nuk.Ingress.model_validate(i) for i in ingress]
    doc = nuk.build_override(name, parsed, *args, **kwargs)
    assert doc is not None
    return doc.to_wire()


# --- override: edge-network join, dedup shared services -----------------------


def test_override_dedups_shared_service():
    # both entries reference frontend; override must list it once
    ov = _override(
        "kolbe",
        [
            {
                "host": "kolbe.astrojones.de",
                "path": "/api",
                "service": "backend",
                "port": 8000,
            },
            {"host": "kolbe.astrojones.de", "service": "frontend", "port": 80},
            {
                "host": "kolbe.astrojones.de",
                "service": "frontend",
                "port": 80,
                "www": True,
            },
        ],
    )
    assert ov["services"] == {
        "backend": {"networks": ["edge"]},
        "frontend": {"networks": ["edge"]},
    }
    assert ov["networks"] == {"edge": {"external": True}}


def test_override_empty_is_none():
    assert nuk.build_override("x", []) is None


# --- override: data-network join + env_file when a database is requested ------


def test_override_with_db_joins_data_and_env_file():
    ov = _override(
        "nukview",
        [{"host": "nuk.astrojones.de", "service": "nukview", "port": 3000}],
        db_env="/opt/nuklaut/secrets/nukview-db.env",
    )
    assert ov["services"] == {
        "nukview": {
            "networks": ["edge", "data"],
            "env_file": ["/opt/nuklaut/secrets/nukview-db.env"],
        }
    }
    assert ov["networks"] == {
        "edge": {"external": True},
        "data": {"external": True},
    }


# --- override: spec.envFrom secretRefs injected via env_file ------------------


def test_resolve_env_from_filters_to_existing_paths(tmp_path):
    present = tmp_path / "present.env"
    present.write_text("FOO=bar\n")
    spec = {
        "envFrom": [
            {"secretRef": str(present)},
            {"secretRef": str(tmp_path / "missing.env")},
            str(tmp_path / "also-missing.env"),
        ]
    }
    assert nuk.resolve_env_from(spec) == [str(present)]


def test_override_env_from_injected_into_ingress_service(tmp_path):
    """spec.envFrom secretRefs must land in the ingress service's env_file —
    that's the only way values reach the container (--env-file only feeds
    ${VAR} interpolation in the compose file, not the container env).
    """
    secret = tmp_path / "app.env"
    secret.write_text("API_KEY=shh\n")
    ov = _override(
        "kolbe",
        [{"host": "kolbe.astrojones.de", "service": "backend", "port": 8000}],
        env_from=[str(secret)],
    )
    assert ov["services"] == {
        "backend": {
            "networks": ["edge"],
            "env_file": [str(secret)],
        }
    }
    assert ov["networks"] == {"edge": {"external": True}}


def test_override_env_from_and_db_env_both_present_db_env_last(tmp_path):
    """When both spec.envFrom and a provisioned database are present, both must
    appear in env_file, with db_env last so DATABASE_URL/REDIS_URL win on any
    key collisions.
    """
    secret = tmp_path / "app.env"
    secret.write_text("API_KEY=shh\n")
    db_env = "/opt/nuklaut/secrets/nukview-db.env"
    ov = _override(
        "nukview",
        [{"host": "nuk.astrojones.de", "service": "nukview", "port": 3000}],
        db_env=db_env,
        env_from=[str(secret)],
    )
    assert ov["services"] == {
        "nukview": {
            "networks": ["edge", "data"],
            "env_file": [str(secret), db_env],
        }
    }
    assert ov["networks"] == {
        "edge": {"external": True},
        "data": {"external": True},
    }


def test_override_without_env_from_or_db_env_has_no_env_file():
    ov = _override("bartix", [{"host": "bartix.de", "service": "web", "port": 8080}])
    assert ov["services"] == {"web": {"networks": ["edge"]}}
    assert "env_file" not in ov["services"]["web"]


def test_write_override_includes_env_from(tmp_path, monkeypatch):
    """End-to-end through write_override: the rendered compose.override.yml for
    an ingress service includes the resolved envFrom secretRef paths.
    """
    deploys = tmp_path / "deployments"
    deploys.mkdir()
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    (deploys / "kolbe").mkdir()

    secret = tmp_path / "app.env"
    secret.write_text("API_KEY=shh\n")

    nuk.write_override(
        "kolbe",
        [nuk.Ingress(host="kolbe.astrojones.de", service="backend", port=8000)],
        env_from=[str(secret)],
    )
    doc = yaml.safe_load((deploys / "kolbe" / "compose.override.yml").read_text())
    assert doc["services"]["backend"]["env_file"] == [str(secret)]


# --- inject DB creds into non-ingress services (issue #8) ---------------------


def test_databases_parses_attach_selectors():
    """spec.databases gains attachAll / attachTo selectors (aliases preserved)."""
    spec = nuk.Spec.model_validate(
        {"databases": {"postgres": True, "redis": True, "attachAll": True}}
    )
    assert spec.databases.attach_all is True
    assert spec.databases.attach_to == []
    spec2 = nuk.Spec.model_validate(
        {"databases": {"postgres": True, "attachTo": ["web", "worker"]}}
    )
    assert spec2.databases.attach_to == ["web", "worker"]
    assert spec2.databases.attach_all is False


def test_override_db_services_default_is_ingress_backcompat():
    """db_services=None keeps the legacy behaviour: ingress services get the db."""
    db_env = "/opt/nuklaut/secrets/app-db.env"
    ov = _override(
        "app", [{"host": "app.de", "service": "web", "port": 8080}], db_env=db_env
    )
    assert ov["services"]["web"] == {"networks": ["edge", "data"], "env_file": [db_env]}
    assert ov["networks"] == {"edge": {"external": True}, "data": {"external": True}}


def test_override_attaches_db_to_explicit_non_ingress_service():
    """An attachTo list extends the db creds + data network onto a worker service
    that has no ingress, while the ingress service keeps edge + db.
    """
    db_env = "/opt/nuklaut/secrets/app-db.env"
    ov = _override(
        "app",
        [{"host": "app.de", "service": "web", "port": 8080}],
        db_env=db_env,
        db_services=["web", "worker"],
    )
    assert ov["services"]["web"] == {"networks": ["edge", "data"], "env_file": [db_env]}
    assert ov["services"]["worker"] == {"networks": ["data"], "env_file": [db_env]}
    assert ov["networks"] == {"edge": {"external": True}, "data": {"external": True}}


def test_override_worker_only_app_receives_db_url_without_edge():
    """A DB-only / worker-only app (no ingress) still gets DATABASE_URL: the
    worker joins the data network and gets the creds env_file, and edge — which
    nothing uses — is omitted entirely.
    """
    db_env = "/opt/nuklaut/secrets/batch-db.env"
    ov = _override("batch", [], db_env=db_env, db_services=["worker"])
    assert ov["services"] == {"worker": {"networks": ["data"], "env_file": [db_env]}}
    assert ov["networks"] == {"data": {"external": True}}


def test_override_attach_to_excluding_ingress_keeps_secrets_but_not_db(tmp_path):
    """When attachTo lists only a worker, the ingress web service keeps its edge
    network + envFrom secrets but is NOT given the db creds/data network.
    """
    secret = tmp_path / "app.env"
    secret.write_text("API_KEY=shh\n")
    db_env = "/opt/nuklaut/secrets/app-db.env"
    ov = _override(
        "app",
        [{"host": "app.de", "service": "web", "port": 8080}],
        db_env=db_env,
        env_from=[str(secret)],
        db_services=["worker"],
    )
    assert ov["services"]["web"] == {"networks": ["edge"], "env_file": [str(secret)]}
    assert ov["services"]["worker"] == {"networks": ["data"], "env_file": [str(secret), db_env]}


def test_build_override_remote_db_skips_local_data_network(tmp_path):
    db_env = str(tmp_path / "app-db.env")
    ov = _override(
        "app",
        [{"host": "app.example.com", "service": "web", "port": 8080}],
        db_env,
        db_services=["web"],
        publish_ip="10.0.10.107",
        local_data=False,
    )
    # The creds still reach the container (DATABASE_URL points at 10.0.10.180),
    # but there is no `data` docker network to join on the app host (spec §3.1).
    assert ov["services"]["web"]["env_file"] == [db_env]
    assert "data" not in ov["services"]["web"]["networks"]
    assert "data" not in (ov.get("networks") or {})


def test_build_override_local_db_still_joins_data_network(tmp_path):
    db_env = str(tmp_path / "app-db.env")
    ov = _override(
        "app",
        [{"host": "app.example.com", "service": "web", "port": 8080}],
        db_env,
        db_services=["web"],
        local_data=True,
    )
    assert ov["services"]["web"]["networks"] == ["edge", "data"]
    assert ov["networks"] == {"edge": {"external": True}, "data": {"external": True}}


def test_compose_service_names_reads_repo_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    repo = tmp_path / "app" / "repo"
    repo.mkdir(parents=True)
    (repo / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"web": {"image": "x"}, "worker": {"image": "y"}}})
    )
    raw = {"spec": {}}
    assert sorted(nuk.compose_service_names("app", raw)) == ["web", "worker"]


def test_compose_service_names_with_bare_string_compose(tmp_path, monkeypatch):
    """spec.compose as a bare string (as shipped by data-stack.yml/ingress.yml)
    must resolve the same as the {file: ...} dict form, not raise AttributeError.
    """
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    repo = tmp_path / "app" / "repo"
    repo.mkdir(parents=True)
    (repo / "docker-compose.data.yml").write_text(
        yaml.safe_dump({"services": {"db": {"image": "x"}}})
    )
    raw = {"spec": {"compose": "docker-compose.data.yml"}}
    assert nuk.compose_service_names("app", raw) == ["db"]


def test_compose_args_with_bare_string_compose(tmp_path, monkeypatch):
    """compose_args must not crash when spec.compose is a bare string."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    project_dir = tmp_path / "app" / "repo"
    project_dir.mkdir(parents=True)
    spec = {"spec": {"compose": "docker-compose.data.yml"}}
    args = nuk.compose_args("app", spec)
    assert str(project_dir / "docker-compose.data.yml") in args


def test_compose_args_with_dict_compose_still_works(tmp_path, monkeypatch):
    """Regression guard: the existing {file: ...} dict form is unaffected."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    project_dir = tmp_path / "app" / "repo"
    project_dir.mkdir(parents=True)
    spec = {"spec": {"compose": {"file": "docker-compose.data.yml"}}}
    args = nuk.compose_args("app", spec)
    assert str(project_dir / "docker-compose.data.yml") in args


def test_load_then_compose_args_with_bare_string_compose(tmp_path, monkeypatch):
    """End-to-end: nuk.load() on a manifest with compose as a bare string
    feeds compose_args via manifest.raw without crashing.
    """
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    project_dir = tmp_path / "app" / "repo"
    project_dir.mkdir(parents=True)
    manifest_path = tmp_path / "app.yml"
    manifest_path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "nuk/v1",
                "kind": "Deployment",
                "metadata": {"name": "app"},
                "spec": {
                    "source": {"repo": "https://example.com/app.git"},
                    "compose": "docker-compose.data.yml",
                },
            }
        )
    )
    manifest = nuk.load(manifest_path)
    args = nuk.compose_args("app", manifest.raw)
    assert str(project_dir / "docker-compose.data.yml") in args
    assert manifest.spec.compose.file == "docker-compose.data.yml"


def test_resolve_db_services_empty_without_db_env():
    raw = {"spec": {"ingress": [{"host": "a", "service": "web", "port": 80}]}}
    assert nuk.resolve_db_services("app", raw, None) == []


def test_resolve_db_services_defaults_to_ingress():
    raw = {"spec": {"ingress": [{"host": "a", "service": "web", "port": 80}]}}
    assert nuk.resolve_db_services("app", raw, "/x/app-db.env") == ["web"]


def test_resolve_db_services_attach_to_wins():
    raw = {
        "spec": {
            "ingress": [{"host": "a", "service": "web", "port": 80}],
            "databases": {"postgres": True, "attachTo": ["web", "worker"]},
        }
    }
    assert nuk.resolve_db_services("app", raw, "/x/app-db.env") == ["web", "worker"]


def test_resolve_db_services_attach_all_enumerates_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    repo = tmp_path / "batch" / "repo"
    repo.mkdir(parents=True)
    (repo / "docker-compose.yml").write_text(
        yaml.safe_dump({"services": {"worker": {"image": "x"}, "beat": {"image": "y"}}})
    )
    raw = {"spec": {"databases": {"postgres": True, "attachAll": True}}}
    assert sorted(nuk.resolve_db_services("batch", raw, "/x/batch-db.env")) == ["beat", "worker"]


# --- database identifier / literal guards -------------------------------------


def test_safe_ident_accepts_dns_and_underscore_names():
    for ok in ("nukview", "kolbe", "my-app", "a1-b2", "a_b"):
        assert nuk._safe_ident(ok) == ok


def test_safe_ident_rejects_injection():
    for bad in ("Drop", "1app", 'a"b', "a;b", "a b", "-x", ""):
        with pytest.raises(SystemExit):
            nuk._safe_ident(bad)


def test_lit_doubles_quotes():
    assert nuk._lit("ok") == "'ok'"
    assert nuk._lit("a'b") == "'a''b'"


def test_pw_from_url_roundtrip():
    url = "postgresql://app:s3cr3t-pw_@nuk-postgres:5432/app"
    assert nuk._pw_from_url(url) == "s3cr3t-pw_"
    assert nuk._pw_from_url(None) is None


# --- provisioning: no-op fast path, creds file IO -----------------------------


def test_provision_databases_noop_without_request():
    assert nuk.provision_databases("app", {}, []) is None
    assert nuk.provision_databases("app", {"postgres": False, "redis": False}, []) is None


def test_db_env_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    written = nuk.write_db_env(
        "app",
        {
            "DATABASE_URL": "postgresql://app:pw@nuk-postgres:5432/app",
            "REDIS_URL": "redis://app:pw@nuk-redis:6379/0",
        },
    )
    assert written == str(tmp_path / "app-db.env")
    assert (tmp_path / "app-db.env").stat().st_mode & 0o777 == 0o600
    assert nuk.read_db_env("app") == {
        "DATABASE_URL": "postgresql://app:pw@nuk-postgres:5432/app",
        "REDIS_URL": "redis://app:pw@nuk-redis:6379/0",
    }


def test_read_db_env_absent_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    assert nuk.read_db_env("nope") == {}


# --- postgres driver scheme (kolbe needs postgresql+asyncpg://) ----------------


def test_ensure_postgres_driver_scheme(monkeypatch):
    """A driver picks the SQLAlchemy-style scheme suffix; None stays bare libpq."""
    monkeypatch.setattr(nuk, "_psql", lambda *a, **k: "")
    url = nuk.ensure_postgres("app", None, "asyncpg")
    assert url.startswith("postgresql+asyncpg://app:")
    assert url.endswith("@nuk-postgres:5432/app")
    bare = nuk.ensure_postgres("app", None)
    assert bare.startswith("postgresql://app:")
    assert "+" not in bare.split("://", 1)[0]


def test_ensure_postgres_rejects_bad_driver(monkeypatch):
    """The driver lands in the URL scheme — reject anything but a lowercase token."""
    monkeypatch.setattr(nuk, "_psql", lambda *a, **k: "")
    for bad in ("as-yncpg", "1pg", "asyncpg;DROP", "Async", "a b"):
        with pytest.raises(SystemExit):
            nuk.ensure_postgres("app", None, bad)


def test_pw_from_url_handles_driver_scheme():
    url = "postgresql+asyncpg://app:p_w-123@nuk-postgres:5432/app"
    assert nuk._pw_from_url(url) == "p_w-123"


def test_provision_databases_extracts_driver(tmp_path, monkeypatch):
    """`postgres: {driver: asyncpg}` passes the driver through; `postgres: true`
    passes None (the backward-compatible bare-URL path nukview relies on).
    """
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a, **k: None)
    monkeypatch.setattr(nuk, "env_facility", lambda *a, **k: object())
    seen: list[str | None] = []

    def fake_pg(app, prev, driver=None):
        seen.append(driver)
        return (f"postgresql+{driver}" if driver else "postgresql") + f"://{app}:x@h:5432/{app}"

    monkeypatch.setattr(nuk, "ensure_postgres", fake_pg)
    nuk.provision_databases("app", {"postgres": {"driver": "asyncpg"}}, [])
    assert seen == ["asyncpg"]
    assert nuk.read_db_env("app")["DATABASE_URL"].startswith("postgresql+asyncpg://")

    nuk.provision_databases("app", {"postgres": True}, [])
    assert seen == ["asyncpg", None]


# --- data-stack preflight (issue #10): own the stack, fail fast & actionably ---


def test_container_state_absent_when_inspect_fails(monkeypatch):
    """A missing container (docker inspect non-zero) reports (exists, healthy)=(False, False)."""

    def fake_run(cmd, *a, **k):
        return nuk.subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No such object")

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    assert nuk._container_state("nuk-postgres") == (False, False)


def test_container_state_running_without_healthcheck_is_healthy(monkeypatch):
    """A running container with no healthcheck block is treated as healthy."""

    def fake_run(cmd, *a, **k):
        return nuk.subprocess.CompletedProcess(cmd, 0, stdout="true none\n", stderr="")

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    assert nuk._container_state("nuk-postgres") == (True, True)


def test_container_state_unhealthy_when_health_reports_unhealthy(monkeypatch):
    def fake_run(cmd, *a, **k):
        return nuk.subprocess.CompletedProcess(cmd, 0, stdout="true unhealthy\n", stderr="")

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    assert nuk._container_state("nuk-redis") == (True, False)


def test_container_state_healthy_when_health_reports_healthy(monkeypatch):
    def fake_run(cmd, *a, **k):
        return nuk.subprocess.CompletedProcess(cmd, 0, stdout="true healthy\n", stderr="")

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    assert nuk._container_state("nuk-postgres") == (True, True)


def _stub_admin_paths(monkeypatch, *, pgvector="1", whoami="nukadmin"):
    """Stub the docker-exec admin helpers so preflight runs without a daemon."""
    monkeypatch.setattr(nuk, "_psql", lambda *a, **k: pgvector)
    monkeypatch.setattr(nuk, "_redis_admin", lambda *a, **k: whoami)


def test_preflight_missing_postgres_is_actionable(monkeypatch):
    """A down postgres aborts with a message naming the container + the owned compose."""
    monkeypatch.setattr(nuk, "_container_state", lambda name: (False, False))
    _stub_admin_paths(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        nuk.preflight_data_stack(want_pg=True, want_redis=False)
    msg = str(exc.value)
    assert nuk.PG_CONTAINER in msg
    assert "docker-compose.data.yml" in msg


def test_preflight_unhealthy_redis_is_actionable(monkeypatch):
    monkeypatch.setattr(nuk, "_container_state", lambda name: (True, False))
    _stub_admin_paths(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        nuk.preflight_data_stack(want_pg=False, want_redis=True)
    assert nuk.REDIS_CONTAINER in str(exc.value)
    assert "healthy" in str(exc.value)


def test_preflight_missing_pgvector_is_actionable(monkeypatch):
    """A healthy postgres without the `vector` extension available still aborts."""
    monkeypatch.setattr(nuk, "_container_state", lambda name: (True, True))
    _stub_admin_paths(monkeypatch, pgvector="")
    with pytest.raises(SystemExit, match="pgvector"):
        nuk.preflight_data_stack(want_pg=True, want_redis=False)


def test_preflight_missing_nukadmin_is_actionable(monkeypatch):
    """A redis where authenticating as nukadmin fails aborts actionably."""
    monkeypatch.setattr(nuk, "_container_state", lambda name: (True, True))
    monkeypatch.setattr(nuk, "_psql", lambda *a, **k: "1")

    def boom(*a, **k):
        raise nuk.subprocess.CalledProcessError(1, ["docker", "exec"])

    monkeypatch.setattr(nuk, "_redis_admin", boom)
    with pytest.raises(SystemExit, match="nukadmin"):
        nuk.preflight_data_stack(want_pg=False, want_redis=True)


def test_preflight_passes_when_stack_healthy(monkeypatch):
    monkeypatch.setattr(nuk, "_container_state", lambda name: (True, True))
    _stub_admin_paths(monkeypatch)
    assert nuk.preflight_data_stack(want_pg=True, want_redis=True) is None


def test_preflight_skips_unrequested_engines(monkeypatch):
    """redis-only provisioning must not inspect/require postgres."""
    seen: list[str] = []
    monkeypatch.setattr(nuk, "_container_state", lambda name: (seen.append(name), (True, True))[1])
    _stub_admin_paths(monkeypatch)
    nuk.preflight_data_stack(want_pg=False, want_redis=True)
    assert seen == [nuk.REDIS_CONTAINER]


def test_provision_databases_runs_preflight_before_exec(tmp_path, monkeypatch):
    """provision_databases preflights before any ensure_* exec and aborts when the
    stack is down — ensure_postgres must never run against an absent container.
    """
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    monkeypatch.setattr(nuk, "_container_state", lambda name: (False, False))
    monkeypatch.setattr(nuk, "env_facility", lambda *a, **k: object())

    def fail(*a, **k):
        pytest.fail("ensure_postgres must not run when preflight fails")

    monkeypatch.setattr(nuk, "ensure_postgres", fail)
    with pytest.raises(SystemExit):
        nuk.provision_databases("app", {"postgres": True}, [])


# --- vendored data stack (issue #10): the owned, reproducible source ----------


def test_data_stack_compose_is_vendored_and_well_formed():
    """files/docker-compose.data.yml is the owned source for the shared stack: it
    must define the nuk-postgres (pgvector) + nuk-redis containers nuk targets and
    the external `data` network apps join.
    """
    from pathlib import Path

    path = Path(nuk.__file__).parent / "files" / "docker-compose.data.yml"
    doc = yaml.safe_load(path.read_text())
    svcs = doc["services"]
    cnames = {s.get("container_name") for s in svcs.values()}
    assert nuk.PG_CONTAINER in cnames
    assert nuk.REDIS_CONTAINER in cnames
    pg = next(s for s in svcs.values() if s.get("container_name") == nuk.PG_CONTAINER)
    assert "pgvector" in pg["image"]
    assert doc["networks"]["data"]["name"] == "data"


# --- source provenance: github_url + manifest stamping ------------------------


@pytest.mark.parametrize(
    "remote,expected",
    [
        ("git@github.com:astrojones/kolbe.git", "https://github.com/astrojones/kolbe"),
        ("https://github.com/astrojones/kolbe.git", "https://github.com/astrojones/kolbe"),
        ("https://github.com/astrojones/kolbe", "https://github.com/astrojones/kolbe"),
        ("git@github.com:astrojones/kolbe", "https://github.com/astrojones/kolbe"),
        ("  https://github.com/astrojones/kolbe.git\n", "https://github.com/astrojones/kolbe"),
    ],
)
def test_github_url_normalises(remote, expected):
    assert nuk.github_url(remote) == expected


@pytest.mark.parametrize(
    "remote",
    ["git@gitlab.com:astrojones/kolbe.git", "", "not a url", "https://example.com/x"],
)
def test_github_url_rejects_non_github(remote):
    assert nuk.github_url(remote) is None


def test_persist_manifest_stamps_source_repo_from_origin(tmp_path, monkeypatch):
    """--repo-path apply: a manifest without spec.source.repo gets one stamped
    from the checkout's git origin, so nukview can link the app to its repo.
    """
    monkeypatch.setattr(nuk, "git_origin", lambda p: "https://github.com/astrojones/kolbe")
    spec = {
        "apiVersion": "nuk/v1",
        "kind": "Deployment",
        "metadata": {"name": "kolbe"},
        "spec": {"ingress": []},
    }
    src = tmp_path / "deployment.yml"
    src.write_text("placeholder")
    dest = tmp_path / "manifest.yml"
    nuk.persist_manifest(spec, src, dest, "/ws")
    out = yaml.safe_load(dest.read_text())
    assert out["spec"]["source"]["repo"] == "https://github.com/astrojones/kolbe"


def test_persist_manifest_preserves_declared_source_repo(tmp_path, monkeypatch):
    """A manifest that already declares spec.source.repo is copied verbatim; the
    declared source wins over the git origin and the file is left untouched.
    """
    monkeypatch.setattr(nuk, "git_origin", lambda p: "https://github.com/astrojones/OTHER")
    spec = {
        "apiVersion": "nuk/v1",
        "kind": "Deployment",
        "metadata": {"name": "x"},
        "spec": {"source": {"repo": "https://github.com/astrojones/declared"}},
    }
    src = tmp_path / "deployment.yml"
    src.write_text("verbatim-content")
    dest = tmp_path / "manifest.yml"
    nuk.persist_manifest(spec, src, dest, "/ws")
    assert dest.read_text() == "verbatim-content"


def test_persist_manifest_verbatim_when_origin_unavailable(tmp_path, monkeypatch):
    """No git origin (e.g. not a github checkout) => plain verbatim copy, no stamp."""
    monkeypatch.setattr(nuk, "git_origin", lambda p: None)
    spec = {"apiVersion": "nuk/v1", "kind": "Deployment", "metadata": {"name": "x"}, "spec": {}}
    src = tmp_path / "deployment.yml"
    src.write_text("verbatim")
    dest = tmp_path / "manifest.yml"
    nuk.persist_manifest(spec, src, dest, None)
    assert dest.read_text() == "verbatim"


def test_persist_manifest_stamps_bare_spec_from_real_git_origin(tmp_path):
    """Regression: a manifest with a bare `spec:` key (YAML null) plus a
    --repo-path checkout with a github origin must stamp source.repo, not
    crash on `spec.setdefault("spec", {})` returning the existing None.
    """
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    def run(*args: str) -> None:
        subprocess.run(args, cwd=checkout, check=True, capture_output=True)  # noqa: S603  # fixed argv, no shell

    run("git", "init", "-q")
    run("git", "remote", "add", "origin", "https://github.com/astrojones/kolbe.git")
    spec = {
        "apiVersion": "nuk/v1",
        "kind": "Deployment",
        "metadata": {"name": "kolbe"},
        "spec": None,
    }
    src = tmp_path / "deployment.yml"
    src.write_text("spec:\n", encoding="utf-8")
    dest = tmp_path / "manifest.yml"
    nuk.persist_manifest(spec, src, dest, str(checkout))
    out = yaml.safe_load(dest.read_text())
    assert out["spec"]["source"]["repo"] == "https://github.com/astrojones/kolbe"


# --- version flag (used by the controller CD smoke check) ---------------------


def test_version_flag_prints_version_and_exits_zero(capsys, monkeypatch):
    """`nuk --version` exits 0 and prints `nuk <__version__>` — the CD deploy
    workflow smoke-tests the freshly installed binary with it. argparse's
    version action runs during parse, before the /opt/nuklaut host check, so it
    works on any machine.
    """
    assert isinstance(nuk.__version__, str) and nuk.__version__
    monkeypatch.setattr(nuk.sys, "argv", ["nuk", "--version"])
    with pytest.raises(SystemExit) as exc:
        nuk.main()
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"nuk {nuk.__version__}"


# --- status <name> (issue #11): single-app health + redacted DB URLs ----------


def test_redact_db_url_masks_password_keeps_scheme_host_db():
    """The password is replaced with ***; scheme, user, host:port and db survive."""
    red = nuk._redact_db_url("postgresql+asyncpg://app:s3cr3t-pw@nuk-postgres:5432/app")
    assert red == "postgresql+asyncpg://app:***@nuk-postgres:5432/app"
    assert "s3cr3t-pw" not in red


def test_redact_db_url_handles_redis_and_passwordless_and_none():
    assert (
        nuk._redact_db_url("redis://app:tok@nuk-redis:6379/0") == "redis://app:***@nuk-redis:6379/0"
    )
    # no password -> returned unchanged (nothing to mask)
    assert nuk._redact_db_url("postgresql://host:5432/db") == "postgresql://host:5432/db"
    assert nuk._redact_db_url(None) is None


def _write_deployment(tmp_path, monkeypatch, *, name="app", with_git=True, manifest=None):
    """Stand up a fake /opt/nuklaut layout for one deployment and patch the roots."""
    deploys = tmp_path / "deployments"
    secrets = tmp_path / "secrets"
    secrets.mkdir(parents=True)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    monkeypatch.setattr(nuk, "SECRETS", secrets)
    pdir = deploys / name
    pdir.mkdir(parents=True)
    if manifest is None:
        manifest = {
            "apiVersion": "nuk/v1",
            "kind": "Deployment",
            "metadata": {"name": name},
            "spec": {
                "source": {"repo": "https://github.com/astrojones/app", "branch": "main"},
                "ingress": [{"host": "app.astrojones.de", "service": "web", "port": 8080}],
            },
        }
    (pdir / "manifest.yml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    if with_git:
        (pdir / "repo" / ".git").mkdir(parents=True)
    return pdir, secrets


def test_status_unknown_deployment_exits(tmp_path, monkeypatch):
    """`nuk status <missing>` aborts (no manifest on the controller)."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deployments")
    with pytest.raises(SystemExit, match="nope"):
        nuk.cmd_status("nope")


def test_status_reports_health_ingress_dbs_and_source(tmp_path, monkeypatch, capsys):
    """The full single-app view: container state, ingress + router health, redacted
    DB URLs (read back from the creds file), and source repo/branch/revision.
    """
    _, secrets = _write_deployment(tmp_path, monkeypatch)
    (secrets / "app-db.env").write_text(
        "DATABASE_URL=postgresql://app:PG-SECRET@nuk-postgres:5432/app\n"
        "REDIS_URL=redis://app:REDIS-SECRET@nuk-redis:6379/0\n"
    )
    monkeypatch.setattr(nuk, "_container_state", lambda c: (True, True))

    def fake_run(cmd, *a, **k):
        if cmd[:2] == ["docker", "compose"]:
            return nuk.subprocess.CompletedProcess(cmd, 0, stdout="web running\n", stderr="")
        if cmd[0] == "git":  # rev-parse --short HEAD
            return nuk.subprocess.CompletedProcess(cmd, 0, stdout="abc1234\n", stderr="")
        return nuk.subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    nuk.cmd_status("app")
    out = capsys.readouterr().out

    # raw passwords must never be surfaced
    assert "PG-SECRET" not in out
    assert "REDIS-SECRET" not in out
    # redacted URLs present
    assert "postgresql://app:***@nuk-postgres:5432/app" in out
    assert "redis://app:***@nuk-redis:6379/0" in out
    # ingress host + router health
    assert "app.astrojones.de" in out
    assert "healthy" in out
    # source provenance
    assert "https://github.com/astrojones/app" in out
    assert "main" in out
    assert "abc1234" in out


def test_status_handles_no_databases_and_workflow_managed_revision(tmp_path, monkeypatch, capsys):
    """No creds file => no DB lines; a workflow-managed deploy (no repo/.git) => the
    revision is reported as unknown rather than crashing.
    """
    _write_deployment(tmp_path, monkeypatch, with_git=False)
    monkeypatch.setattr(nuk, "_container_state", lambda c: (False, False))
    monkeypatch.setattr(
        nuk.subprocess,
        "run",
        lambda cmd, *a, **k: nuk.subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
    )
    nuk.cmd_status("app")
    out = capsys.readouterr().out
    assert "none provisioned" in out
    # no .git -> git is never shelled out to; revision shown as unknown
    assert "-" in out


# --- shell completion (issue #12): enable + dynamic deployment-name completer --


def test_completion_options_exposed():
    """add_completion is on, so the controller gets --install/--show-completion.

    Introspect the built click command instead of asserting on the Rich-rendered
    --help: with no TTY (CI) Rich falls back to a narrow width and truncates the
    option name to `--install-complet…`, so a substring check on the help text is
    width-dependent. The params themselves are what `add_completion=True` adds.
    """
    import typer.main

    params = {p.name for p in typer.main.get_command(nuk.app).params}
    assert "install_completion" in params
    assert "show_completion" in params


def test_known_deployments_enumerates_manifest_dirs(tmp_path, monkeypatch):
    """The completer source mirrors cmd_get: only dirs carrying a manifest.yml."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    for n in ("alpha", "beta"):
        (tmp_path / n).mkdir()
        (tmp_path / n / "manifest.yml").write_text("x")
    (tmp_path / "no-manifest").mkdir()  # a stray dir without a manifest is ignored
    assert nuk._known_deployments() == ["alpha", "beta"]


def test_known_deployments_empty_when_root_absent(tmp_path, monkeypatch):
    """Off-controller (no /opt/nuklaut), completion degrades to empty, never raises."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "missing")
    assert nuk._known_deployments() == []


def test_complete_deployment_name_prefix_filters(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    for n in ("alpha", "apex", "beta"):
        (tmp_path / n).mkdir()
        (tmp_path / n / "manifest.yml").write_text("x")
    assert nuk.complete_deployment_name("a") == ["alpha", "apex"]


@pytest.mark.parametrize("command", ["logs", "rollout", "delete", "status"])
def test_deployment_name_arg_completes_real_apps(command, tmp_path, monkeypatch):
    """Each deployment-name argument resolves real app names through click's public
    shell-completion path — so `nuk <command> <TAB>` suggests live deployments.
    Includes the new `status` command (issue #11 ∩ #12).
    """
    import typer.main
    from typer.main import _click as click  # typer 0.26 bundles its own click

    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    (tmp_path / "kolbe").mkdir()
    (tmp_path / "kolbe" / "manifest.yml").write_text("x")
    cmd = typer.main.get_command(nuk.app).commands[command]
    param = next(p for p in cmd.params if p.name == "name")
    completions = param.shell_complete(click.Context(cmd), "")
    assert "kolbe" in [c.value for c in completions]


# --- manifest path back-compat (root deployment.yml -> legacy .nuklaut/) -------


def test_resolve_manifest_prefers_root(tmp_path):
    root = tmp_path / "deployment.yml"
    root.write_text("x")
    (tmp_path / ".nuklaut").mkdir()
    (tmp_path / ".nuklaut" / "deployment.yml").write_text("y")
    assert nuk.resolve_manifest(root) == root


def test_resolve_manifest_falls_back_to_legacy(tmp_path):
    legacy = tmp_path / ".nuklaut" / "deployment.yml"
    legacy.parent.mkdir()
    legacy.write_text("x")
    assert nuk.resolve_manifest(tmp_path / "deployment.yml") == legacy


def test_resolve_manifest_returns_original_when_neither_exists(tmp_path):
    missing = tmp_path / "deployment.yml"
    assert nuk.resolve_manifest(missing) == missing


# --- finding 6: a worker app terminates its ingress on the edge ---------------


def test_read_self_parses_role_and_ip(tmp_path, monkeypatch):
    he = tmp_path / "host.env"
    he.write_text("ROLE=app\nPRIVATE_IP=10.0.1.20\n")
    monkeypatch.setattr(nuk, "HOST_ENV", he)
    assert nuk.read_self() == ("app", "10.0.1.20")


def test_read_self_absent_defaults_to_entry_role(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "HOST_ENV", tmp_path / "nope.env")
    role, ip = nuk.read_self()
    assert role in nuk._ENTRY_ROLES  # legacy single-host controller keeps writing locally
    assert ip is None


def test_override_publish_ip_binds_private_ip_and_drops_edge():
    ov = _override(
        "hello",
        [{"host": "hello.modl-agent.com", "service": "web", "port": 8080}],
        publish_ip="10.0.1.20",
    )
    assert ov["services"] == {"web": {"networks": [], "ports": ["10.0.1.20:8080:8080"]}}
    assert ov["networks"] == {}  # no local edge network on a worker


def test_override_publish_ip_with_db_keeps_data_network():
    ov = _override(
        "hello",
        [{"host": "hello.modl-agent.com", "service": "web", "port": 8080}],
        db_env="/opt/nuklaut/secrets/hello-db.env",
        publish_ip="10.0.1.20",
    )
    assert ov["services"]["web"]["ports"] == ["10.0.1.20:8080:8080"]
    assert ov["services"]["web"]["networks"] == ["data"]
    assert ov["services"]["web"]["env_file"] == ["/opt/nuklaut/secrets/hello-db.env"]
    assert ov["networks"] == {"data": {"external": True}}


def test_override_publish_ip_none_is_byte_identical_to_legacy():
    ingress = [{"host": "hello.modl-agent.com", "service": "web", "port": 8080}]
    assert _override("hello", ingress, publish_ip=None) == _override("hello", ingress)


def test_host_port_overrides_publish_to_avoid_collision():
    """Two worker apps sharing container port 8080 must not collide on the host.
    hostPort remaps the HOST side the app publishes on.
    """
    ingress = [{"host": "b.modl-agent.com", "service": "web", "port": 8080, "hostPort": 8081}]
    ov = _override("b", ingress, publish_ip="10.0.1.20")
    assert ov["services"]["web"]["ports"] == ["10.0.1.20:8081:8080"]  # host 8081 -> container 8080


def test_host_port_field_parses_via_alias():
    assert nuk.Ingress(host="h", service="s", port=8080, hostPort=8081).host_port == 8081
    assert nuk.Ingress(host="h", service="s", port=8080).host_port is None


def test_compose_args_tolerates_null_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "project_dir", lambda _n: tmp_path)
    args = nuk.compose_args("app", {"spec": {"compose": None}})
    assert args[0:2] == ["docker", "compose"]


def test_compose_service_names_tolerates_null_compose(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "project_dir", lambda _n: tmp_path)
    assert nuk.compose_service_names("app", {"spec": {"compose": None}}) == []
