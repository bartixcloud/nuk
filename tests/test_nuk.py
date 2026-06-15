"""Unit tests for nuk's pure render functions (build_ingress / build_override).

These need only pyyaml — no /opt/nuklaut, no docker, no controller.

    uv run pytest
"""

from __future__ import annotations

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
    doc = nuk.build_ingress("bartix", [{"host": "bartix.de", "service": "web", "port": 8080}])
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
    assert nuk.build_ingress("x", []) is None
    assert nuk.build_ingress("x", None) is None


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
    doc = nuk.build_ingress("a", [{"host": "h", "path": "/x", "service": "s", "port": 1}])
    assert doc["http"]["routers"]["a-0"]["rule"] == "Host(`h`) && PathPrefix(`/x`)"
    assert doc["http"]["routers"]["a-0"]["middlewares"] == ["maintenance-errors@file"]
    # no app-local middleware DEFINITIONS (maintenance-errors lives in global.yml)
    assert "middlewares" not in doc["http"]


def test_every_app_router_inherits_maintenance_errors():
    """The www-redirect router is the one exception — it 301s, no backend to guard."""
    doc = nuk.build_ingress(
        "kolbeapp",
        [{"host": "kolbeapp.de", "service": "frontend", "port": 80, "www": True}],
    )
    routers = doc["http"]["routers"]
    assert routers["kolbeapp-0"]["middlewares"] == ["maintenance-errors@file"]
    assert routers["kolbeapp-0-www"]["middlewares"] == ["kolbeapp-0-www-redirect"]


def test_auth_oauth_prepends_forwardauth_chain():
    """auth: oauth gates a router via the shared oauth2-proxy GitHub chain,
    ordered errors-then-auth like the Traefik dashboard, ahead of the inherited
    maintenance-errors reference. All three are cross-file (@file) references, so
    no app-local middleware definitions are emitted.
    """
    doc = nuk.build_ingress(
        "nukview",
        [
            {
                "host": "nuk.astrojones.de",
                "service": "nukview",
                "port": 3000,
                "auth": "oauth",
            }
        ],
    )
    assert doc["http"]["routers"]["nukview-0"]["middlewares"] == [
        "oauth-errors@file",
        "oauth-auth@file",
        "maintenance-errors@file",
    ]
    assert "middlewares" not in doc["http"]


def test_auth_oauth_with_pathprefix_orders_oauth_then_strip():
    """When a path is stripped too, the oauth chain stays outermost, then strip,
    then the maintenance reference.
    """
    doc = nuk.build_ingress(
        "api",
        [
            {
                "host": "h",
                "path": "/api",
                "stripPrefix": True,
                "service": "s",
                "port": 1,
                "auth": "oauth",
            }
        ],
    )
    assert doc["http"]["routers"]["api-0"]["middlewares"] == [
        "oauth-errors@file",
        "oauth-auth@file",
        "api-0-strip",
        "maintenance-errors@file",
    ]


def test_explicit_priority():
    doc = nuk.build_ingress("a", [{"host": "h", "service": "s", "port": 1, "priority": 100}])
    assert doc["http"]["routers"]["a-0"]["priority"] == 100


# --- www redirect (opt-in, apex domains) --------------------------------------


def test_www_redirect_router_and_middleware():
    doc = nuk.build_ingress(
        "kolbeapp",
        [
            {"host": "kolbeapp.de", "service": "frontend", "port": 80, "www": True},
        ],
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


# --- override: edge-network join, dedup shared services -----------------------


def test_override_dedups_shared_service():
    # both entries reference frontend; override must list it once
    ov = nuk.build_override(
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
    ov = nuk.build_override(
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
    ov = nuk.build_override(
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
    ov = nuk.build_override(
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
    ov = nuk.build_override("bartix", [{"host": "bartix.de", "service": "web", "port": 8080}])
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
        [{"host": "kolbe.astrojones.de", "service": "backend", "port": 8000}],
        env_from=[str(secret)],
    )
    doc = yaml.safe_load((deploys / "kolbe" / "compose.override.yml").read_text())
    assert doc["services"]["backend"]["env_file"] == [str(secret)]


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
    assert nuk.provision_databases("app", {}) is None
    assert nuk.provision_databases("app", {"postgres": False, "redis": False}) is None


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
    seen: list[str | None] = []

    def fake_pg(app, prev, driver=None):
        seen.append(driver)
        return (f"postgresql+{driver}" if driver else "postgresql") + f"://{app}:x@h:5432/{app}"

    monkeypatch.setattr(nuk, "ensure_postgres", fake_pg)
    nuk.provision_databases("app", {"postgres": {"driver": "asyncpg"}})
    assert seen == ["asyncpg"]
    assert nuk.read_db_env("app")["DATABASE_URL"].startswith("postgresql+asyncpg://")

    nuk.provision_databases("app", {"postgres": True})
    assert seen == ["asyncpg", None]


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
