"""Integration tier (issue #9): real postgres + redis provisioning/purge.

These exercise the parts the unit suite monkeypatches out — the actual SQL /
redis-CLI execution behind `provision_databases` / `purge_databases` — against
the vendored shared data stack (issue #10's `files/docker-compose.data.yml`).
They also exercise issue #10's `preflight_data_stack` (run inside provisioning)
and issue #8's non-ingress injection (against a real, provisioned creds file).

Opt-in only: gated by `@pytest.mark.integration` + the NUK_INTEGRATION env flag
(see tests/conftest.py). The default `uv run pytest` skips them entirely, so the
unit run needs no docker and no /opt/nuklaut.

    NUK_INTEGRATION=1 POSTGRES_PASSWORD=… REDIS_ADMIN_PASSWORD=… \
        uv run pytest -m integration
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import nuk
import pytest

pytestmark = pytest.mark.integration

COMPOSE = Path(nuk.__file__).parent / "files" / "docker-compose.data.yml"
APP = "itest_app"


@pytest.fixture(scope="session")
def data_stack():
    """Bring the vendored shared data stack up (healthy) for the session."""
    env = {
        **os.environ,
        "POSTGRES_PASSWORD": os.environ.get("POSTGRES_PASSWORD", "itest_pg"),
        "REDIS_ADMIN_PASSWORD": os.environ.get("REDIS_ADMIN_PASSWORD", "itest_redis"),
    }
    base = ["docker", "compose", "-f", str(COMPOSE)]
    subprocess.run([*base, "up", "-d", "--wait"], check=True, env=env)  # noqa: S603, S607
    try:
        yield
    finally:
        subprocess.run([*base, "down", "-v"], check=False, env=env)  # noqa: S603, S607


@pytest.fixture
def secrets_dir(tmp_path, monkeypatch):
    """Point nuk's creds store at a throwaway dir for the test."""
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    return tmp_path


@pytest.fixture
def provisioned(data_stack, secrets_dir):
    """Provision postgres+redis for APP, yield its creds, and purge after."""
    dbs = nuk.Databases.model_validate({"postgres": {"driver": "asyncpg"}, "redis": True})
    nuk.provision_databases(APP, dbs, [])
    try:
        yield nuk.read_db_env(APP)
    finally:
        nuk.purge_databases(APP)


def test_preflight_passes_against_the_real_stack(data_stack):
    """#10: a healthy vendored stack (pgvector + nukadmin) clears preflight."""
    assert nuk.preflight_data_stack(want_pg=True, want_redis=True) is None


def test_provision_creates_isolated_role_db_and_pgvector(provisioned):
    """#9: role + database exist, pgvector is enabled, and CONNECT is revoked
    from PUBLIC (only the owner role may connect).
    """
    assert nuk._psql(f"SELECT 1 FROM pg_roles WHERE rolname = {nuk._lit(APP)};") == "1"
    assert nuk._psql(f"SELECT 1 FROM pg_database WHERE datname = {nuk._lit(APP)};") == "1"
    assert nuk._psql("SELECT 1 FROM pg_extension WHERE extname = 'vector';", db=APP) == "1"

    def can_connect(grantee: str) -> str:
        return nuk._psql(
            f"SELECT has_database_privilege({nuk._lit(grantee)}, {nuk._lit(APP)}, 'CONNECT');"
        )

    assert can_connect("public") == "f"
    assert can_connect(APP) == "t"


def test_provision_scopes_redis_acl_to_app_prefix(provisioned):
    """#9: the redis ACL user is scoped to its own ~app:* keyspace."""
    acl = nuk._redis_admin("ACL", "GETUSER", APP)
    assert f"~{APP}:*" in acl


def test_reapply_is_idempotent_and_reuses_password(provisioned):
    """#9: re-applying reuses the stored password rather than churning creds."""
    before = provisioned["DATABASE_URL"], provisioned["REDIS_URL"]
    dbs = nuk.Databases.model_validate({"postgres": {"driver": "asyncpg"}, "redis": True})
    nuk.provision_databases(APP, dbs, [])
    after = nuk.read_db_env(APP)
    assert (after["DATABASE_URL"], after["REDIS_URL"]) == before


def test_injection_attaches_real_creds_to_a_worker(provisioned, secrets_dir):
    """#8 against a real creds file: a worker with no ingress, selected via
    attachTo, receives the provisioned DATABASE_URL via the creds env_file + the
    data network.
    """
    db_env = str(secrets_dir / f"{APP}-db.env")
    raw = {
        "spec": {
            "ingress": [{"host": "app.de", "service": "web", "port": 8080}],
            "databases": {"postgres": True, "attachTo": ["web", "worker"]},
        }
    }
    db_services = nuk.resolve_db_services(APP, raw, db_env)
    assert db_services == ["web", "worker"]
    ov = nuk.build_override(APP, raw["spec"]["ingress"], db_env=db_env, db_services=db_services)
    assert ov["services"]["worker"] == {"networks": ["data"], "env_file": [db_env]}
    assert "DATABASE_URL" in nuk.read_db_env(APP)


def test_purge_drops_db_role_acl_user_and_creds(data_stack, secrets_dir):
    """#9: purge_databases drops the db + role, deletes the redis ACL user, and
    removes the creds file.
    """
    dbs = nuk.Databases.model_validate({"postgres": True, "redis": True})
    nuk.provision_databases(APP, dbs, [])
    assert (secrets_dir / f"{APP}-db.env").exists()

    nuk.purge_databases(APP)

    assert nuk._psql(f"SELECT 1 FROM pg_roles WHERE rolname = {nuk._lit(APP)};") == ""
    assert nuk._psql(f"SELECT 1 FROM pg_database WHERE datname = {nuk._lit(APP)};") == ""
    assert nuk._redis_admin("ACL", "GETUSER", APP) == ""
    assert not (secrets_dir / f"{APP}-db.env").exists()
