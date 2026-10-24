#!/usr/bin/env python3
"""Shared databases: postgres + redis provisioning helpers."""

from __future__ import annotations

import re
import secrets
import subprocess  # noqa: S404
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import nuk
from nuk.util import (
    _chown_deploy,
    _read_env_file,
    die,
)

if TYPE_CHECKING:
    from nuk.models import Databases, Facility
    from nuk.org import Org

# --- shared databases (postgres + redis) -------------------------------------
# A deployment opts in via `spec.databases: {postgres: true, redis: true}`. nuk
# provisions a per-app Postgres role+database (pgvector enabled) and/or a per-app
# Redis ACL user against the shared data stack — on this host when it owns the
# `databases` facility, else it only derives the creds for the remote data host
# (§3.1). Passwords derive from the fleet seed (random-once without one) and land
# in /opt/nuklaut/secrets/<app>-db.env (600). The generated override wires that
# file (env_file) onto the DB services (ingress by default, or attachTo/attachAll),
# so the container starts with DATABASE_URL / REDIS_URL set.
#
# Admin paths never need a TCP password: psql uses the container's local-socket
# trust; redis-cli reads REDIS_ADMIN_PASSWORD from the container's own env.


def _lit(s: str) -> str:
    """Return a safely single-quoted SQL string literal (doubles embedded quotes)."""
    return "'" + s.replace("'", "''") + "'"


def _pw_from_url(url: str | None) -> str | None:
    """Extract the password from a database URL, or None."""
    return urlparse(url).password if url else None


def _redact_db_url(url: str | None) -> str | None:
    """Mask the password in a DB URL, preserving scheme/user/host:port/db.

    `nuk status` surfaces the provisioned DATABASE_URL/REDIS_URL so an operator
    can see *what* was injected without exposing the secret — the raw creds file
    (600, in SECRETS) is never printed. A URL with no password is returned as-is.

    Args:
        url: A connection URL (e.g. postgresql://app:pw@host:5432/app), or None.

    Returns:
        The URL with any password replaced by ``***``, or None for a None input.
    """
    if not url:
        return None
    parts = urlparse(url)
    if parts.password is None:
        return url
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    userinfo = f"{parts.username}:***@" if parts.username else "***@"
    return f"{parts.scheme}://{userinfo}{host}{port}{parts.path}"


def read_db_env(app: str) -> dict[str, str]:
    """Read an app's persisted DB creds env-file into a dict (empty if absent)."""
    path = nuk._db_env_path(app)
    return _read_env_file(path) if path.exists() else {}


def write_db_env(app: str, env: dict[str, str]) -> str:
    """Write an app's DB creds env-file (600, deploy-owned); return its path."""
    nuk.paths.SECRETS.mkdir(parents=True, exist_ok=True)
    path = nuk._db_env_path(app)
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    path.chmod(0o600)
    _chown_deploy(path)
    return str(path)


def _psql(sql: str, db: str = "postgres") -> str:
    """Run a SQL statement in the shared postgres container, returning stdout.

    SQL is composed with `_safe_ident`/`_lit`-guarded identifiers and literals.
    """
    return subprocess.run(  # noqa: S603  # fixed argv, no shell; SQL guarded by _safe_ident/_lit
        [  # noqa: S607  # docker on PATH
            "docker",
            "exec",
            "-i",
            nuk.PG_CONTAINER,
            "psql",
            "-U",
            "postgres",
            "-d",
            db,
            "-v",
            "ON_ERROR_STOP=1",
            "-tAqc",
            sql,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _redis_admin(*redis_args: str) -> str:
    """Run a redis-cli admin command in the shared redis container as nukadmin."""
    # Auth as nukadmin using the password from the container's own env, so it
    # never lands on a host process-arg line.
    script = 'REDISCLI_AUTH="$REDIS_ADMIN_PASSWORD" exec redis-cli --user nukadmin "$@"'
    return subprocess.run(  # noqa: S603  # fixed argv; password read from container env, not argv
        ["docker", "exec", nuk.REDIS_CONTAINER, "sh", "-c", script, "_", *redis_args],  # noqa: S607  # docker on PATH
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


_DATA_STACK_HINT = (
    "bring the shared data stack up with "
    "`docker compose -f files/docker-compose.data.yml up -d` (vendored in this repo)"
)


def _container_state(name: str) -> tuple[bool, bool]:
    """Return `(exists, healthy)` for a container via `docker inspect`.

    `healthy` is True when the container is running and either declares no
    healthcheck or reports a healthy one. An absent container (inspect exits
    non-zero) is `(False, False)`.

    Args:
        name: The container name to inspect.

    Returns:
        A `(exists, healthy)` pair.
    """
    proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
        [  # noqa: S607  # docker on PATH
            "docker",
            "inspect",
            "-f",
            "{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
            name,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return (False, False)
    parts = proc.stdout.strip().split()
    running = bool(parts) and parts[0] == "true"
    health = parts[1] if len(parts) > 1 else "none"
    return (True, running and health in {"healthy", "none"})


def preflight_data_stack(want_pg: bool, want_redis: bool) -> None:
    """Verify the shared data stack is provisionable before any `docker exec`.

    Each requested engine's container must exist and be healthy, and the
    capability provisioning relies on must be present (pgvector available for
    postgres; the `nukadmin` admin user reachable for redis). Failing fast here
    turns an opaque mid-provision `docker exec` error into one actionable line.

    Args:
        want_pg: Whether postgres provisioning was requested.
        want_redis: Whether redis provisioning was requested.

    Raises:
        NukError: When a required container is missing/unhealthy, pgvector is
            unavailable, or the redis `nukadmin` user cannot be reached.
    """
    if want_pg:
        _require_container(nuk.PG_CONTAINER, "postgres")
        if nuk._psql("SELECT 1 FROM pg_available_extensions WHERE name = 'vector';") != "1":
            die(
                f"nuk: pgvector not available in {nuk.PG_CONTAINER!r} — the data stack image "
                f"must provide the 'vector' extension (use pgvector/pgvector)"
            )
    if want_redis:
        _require_container(nuk.REDIS_CONTAINER, "redis")
        try:
            whoami = nuk._redis_admin("ACL", "WHOAMI")
        except subprocess.CalledProcessError:
            whoami = ""
        if whoami != "nukadmin":
            die(
                f"nuk: redis 'nukadmin' admin user not reachable in "
                f"{nuk.REDIS_CONTAINER!r} — {_DATA_STACK_HINT}"
            )


def _require_container(container: str, label: str) -> None:
    """Abort with an actionable message unless `container` exists and is healthy."""
    exists, healthy = nuk._container_state(container)
    if not exists:
        die(f"nuk: shared {label} container {container!r} not found — {_DATA_STACK_HINT}")
    if not healthy:
        die(f"nuk: shared {label} container {container!r} not healthy — {_DATA_STACK_HINT}")


def load_db_seed() -> bytes | None:
    """Read NUK_DB_SEED from the converge-delivered seed file, or None if absent.

    Absent means a legacy single-host install: callers keep the random-password
    behavior so old deploys are byte-identical.
    """
    if not nuk.paths.DB_SEED_ENV.exists():
        return None
    seed = _read_env_file(nuk.paths.DB_SEED_ENV).get("NUK_DB_SEED")
    return seed.encode() if seed is not None else None


def derive_db_password(seed: bytes, kind: str, app: str) -> str:
    """Derive an app's DB password deterministically from the fleet seed.

    SPEC-STABLE (spec §3.1): HKDF-SHA-256, info `nuk-db:<kind>:<app>`, empty
    salt, 32 bytes, base64url without padding. Both the data host (which sets the
    role's password) and the app host (which builds DATABASE_URL) derive the same
    value independently. Changing this is a fleet-wide password rotation.

    Args:
        seed: The fleet seed bytes.
        kind: "pg" or "redis".
        app: The app name.

    Returns:
        A URL-safe ASCII password.
    """
    import base64
    import hashlib
    import hmac

    if kind not in {"pg", "redis"}:
        die(f"nuk: derive_db_password kind must be 'pg' or 'redis', got {kind!r}")
    info = f"nuk-db:{kind}:{app}".encode()
    # RFC 5869 HKDF-SHA-256, salt = HashLen zeros (i.e. empty salt), one block.
    prk = hmac.new(b"\x00" * 32, seed, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(okm).rstrip(b"=").decode()


def _db_password(kind: str, app: str, prev_url: str | None) -> str:
    """Seed-derived when the fleet seed is present, else the previously issued one, else new."""
    seed = nuk.load_db_seed()
    if seed is not None:
        return nuk.derive_db_password(seed, kind, app)
    return _pw_from_url(prev_url) or secrets.token_urlsafe(24)


def _pg_driver(pg: object) -> str | None:
    """The driver from raw `spec.databases.postgres` (bare `true` has none)."""
    driver = pg.get("driver") if isinstance(pg, dict) else None
    return driver if isinstance(driver, str) else None


def _pg_url(app: str, pw: str, host: str, driver: str | None, db: str | None = None) -> str:
    """DATABASE_URL for an app's database; `driver` picks the SQLAlchemy scheme suffix."""
    scheme = f"postgresql+{driver}" if driver else "postgresql"
    return f"{scheme}://{app}:{pw}@{host}:5432/{db or app}"


def _redis_url(app: str, pw: str, host: str) -> str:
    """REDIS_URL for an app's ACL user."""
    return f"redis://{app}:{pw}@{host}:6379/0"


def ensure_postgres(app: str, prev_url: str | None, driver: str | None = None) -> str:
    """Idempotently create role + database (pgvector enabled) for `app`.

    Re-uses the existing password so re-applies don't churn creds. `driver`
    picks the SQLAlchemy-style scheme suffix (e.g. "asyncpg" yields
    postgresql+asyncpg://); None yields the bare libpq postgresql:// URL.

    Args:
        app: The app/database/role name (must be a safe identifier).
        prev_url: A previously-issued URL to reuse the password from, if any.
        driver: Optional SQLAlchemy driver token for the URL scheme.

    Returns:
        A DATABASE_URL for the provisioned database.

    Raises:
        NukError: When `driver` is not a lowercase token.
    """
    if driver and not re.fullmatch(r"[a-z][a-z0-9]*", driver):
        die(f"nuk: invalid postgres driver {driver!r}")
    pw = _db_password("pg", app, prev_url)
    nuk._psql(
        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {_lit(app)}) "
        f'THEN CREATE ROLE "{app}" LOGIN; END IF; END $$;'  # noqa: S608  # app guarded by _safe_ident
    )
    nuk._psql(f'ALTER ROLE "{app}" WITH LOGIN PASSWORD {_lit(pw)};')  # noqa: S608  # app/pw guarded
    if nuk._psql(f"SELECT 1 FROM pg_database WHERE datname = {_lit(app)};") != "1":  # noqa: S608  # _lit-quoted
        nuk._psql(f'CREATE DATABASE "{app}" OWNER "{app}";')  # noqa: S608  # app guarded by _safe_ident
    # Isolate: only the owner role may connect to this database.
    nuk._psql(f'REVOKE CONNECT ON DATABASE "{app}" FROM PUBLIC;')  # noqa: S608  # app guarded
    nuk._psql(f'GRANT CONNECT ON DATABASE "{app}" TO "{app}";')  # noqa: S608  # app guarded
    nuk._psql("CREATE EXTENSION IF NOT EXISTS vector;", db=app)
    return nuk._pg_url(app, pw, nuk.PG_CONTAINER, driver)


def scratch_db_name(app: str) -> str:
    """The scratch database name for `app`, refusing names Postgres would truncate.

    Args:
        app: The app name (must be a safe identifier).

    Returns:
        `"<app>-scratch"`.

    Raises:
        NukError: When `app` is not a safe identifier, or the result exceeds
            Postgres' 63-byte NAMEDATALEN limit (fail closed rather than let the
            server silently truncate a shared prefix).
    """
    name = f"{nuk._safe_ident(app)}-scratch"
    if len(name.encode()) > 63:
        die(f"nuk: database name {name!r} exceeds Postgres' 63-byte limit")
    return name


def ensure_scratch_postgres(app: str, pw: str, driver: str | None) -> str:
    """Idempotently create the scratch database owned by `app`'s existing role.

    The role and password come from `ensure_postgres`; this only adds the second
    database with the same connect isolation and pgvector enabled. Its contents
    belong to the app: nuk never creates, empties or drops it here.

    Args:
        app: The app/role name (must be a safe identifier).
        pw: The password already issued for `app`'s role.
        driver: Optional SQLAlchemy driver token for the URL scheme.

    Returns:
        A SCRATCH_DATABASE_URL for the provisioned database.
    """
    db = scratch_db_name(app)
    if nuk._psql(f"SELECT 1 FROM pg_database WHERE datname = {_lit(db)};") != "1":  # noqa: S608  # _lit-quoted
        nuk._psql(f'CREATE DATABASE "{db}" OWNER "{app}";')  # noqa: S608  # guarded by _safe_ident
    # Isolate: only the owner role may connect to this database.
    nuk._psql(f'REVOKE CONNECT ON DATABASE "{db}" FROM PUBLIC;')  # noqa: S608  # guarded
    nuk._psql(f'GRANT CONNECT ON DATABASE "{db}" TO "{app}";')  # noqa: S608  # guarded
    nuk._psql("CREATE EXTENSION IF NOT EXISTS vector;", db=db)
    return nuk._pg_url(app, pw, nuk.PG_CONTAINER, driver, db=db)


def ensure_redis(app: str, prev_url: str | None) -> str:
    """Idempotently (re-)create a per-app Redis ACL user.

    The user is limited to its own key prefix + channels, with dangerous
    commands removed (no FLUSHALL on the shared instance). Persists to the
    aclfile.

    Args:
        app: The app name (used as the ACL username and key/channel prefix).
        prev_url: A previously-issued URL to reuse the password from, if any.

    Returns:
        A REDIS_URL for the provisioned user.
    """
    pw = _db_password("redis", app, prev_url)
    nuk._redis_admin(
        "ACL",
        "SETUSER",
        app,
        "reset",
        "on",
        f">{pw}",
        f"~{app}:*",
        f"&{app}:*",
        "+@all",
        "-@dangerous",
    )
    nuk._redis_admin("ACL", "SAVE")
    return nuk._redis_url(app, pw, nuk.REDIS_CONTAINER)


def data_host_ip(org: Org) -> str | None:
    """Return the privateIp of the org's `data` host, or None if undeclared."""
    host = org.host_for("data")
    return host.private_ip if host else None


def provision_databases(
    app: str, databases: Databases, facilities: list[Facility], *, remote_ip: str | None = None
) -> str | None:
    """Provision the databases a manifest requested.

    Args:
        app: The app name.
        databases: The manifest's `spec.databases`.
        facilities: The tree's Facility manifests, to check the `databases`
            env capability is actually declared before binding against it.
        remote_ip: The data host's private IP when this host is NOT the data
            host; then this host only derives creds (spec §3.1). None means the
            local data stack is provisioned, exactly as before.

    Returns:
        The path to the creds env-file the override should inject, or None when
        no databases are requested.
    """
    want_pg = databases.wants_postgres
    want_redis = databases.wants_redis
    if not (want_pg or want_redis):
        return None
    # Fail closed before touching the data stack: binding against a facility the
    # org never declared writes half a per-app state (role, database, ACL user)
    # that nothing owns and nothing will tear down (spec §5.4).
    #
    # An EMPTY list is not that case: it means the tree ships no facilities/ dir
    # at all — the legacy single-host topology spec §12 protects, which never had
    # a facility to declare. Same asymmetry route_vocabulary gets in cmd_apply
    # (`route_vocabulary(facilities) if facilities else DEFAULT_ROUTE_VOCAB`):
    # only a tree that opted INTO facilities and still omits this one is refused.
    if facilities and nuk.env_facility(facilities, nuk._DATABASES_CAPABILITY) is None:
        die(
            f"{app}: spec.databases requests {nuk._DATABASES_CAPABILITY!r} but no facility "
            f"provides it. Apply facilities/data-stack.yml first, or drop spec.databases."
        )
    nuk._safe_ident(app)
    if remote_ip is not None:
        # The app host derives; it never provisions (spec §3.1 topology condition).
        seed = nuk.load_db_seed()
        if seed is None:
            die(
                f"{app}: spec.databases needs the fleet DB seed at {nuk.paths.DB_SEED_ENV} "
                f"to derive remote credentials — deliver it via converge.sh"
            )
        env: dict[str, str] = {}  # remote mode derives fresh; never carry stale keys
        if want_pg:
            pw = nuk.derive_db_password(seed, "pg", app)
            env["DATABASE_URL"] = nuk._pg_url(app, pw, remote_ip, databases.postgres_driver)
            if databases.postgres_scratch:
                env["SCRATCH_DATABASE_URL"] = nuk._pg_url(
                    app,
                    pw,
                    remote_ip,
                    databases.postgres_driver,
                    db=nuk.scratch_db_name(app),
                )
        if want_redis:
            env["REDIS_URL"] = nuk._redis_url(
                app, nuk.derive_db_password(seed, "redis", app), remote_ip
            )
        return nuk.write_db_env(app, env)
    nuk.preflight_data_stack(want_pg, want_redis)
    prev = nuk.read_db_env(app)
    env = {}
    if want_pg:
        env["DATABASE_URL"] = nuk.ensure_postgres(
            app, prev.get("DATABASE_URL"), databases.postgres_driver
        )
        if databases.postgres_scratch:
            pw = _pw_from_url(env["DATABASE_URL"])
            if pw is None:
                die(f"{app}: cannot derive the scratch database password from DATABASE_URL")
            env["SCRATCH_DATABASE_URL"] = nuk.ensure_scratch_postgres(
                app, pw, databases.postgres_driver
            )
    if want_redis:
        env["REDIS_URL"] = nuk.ensure_redis(app, prev.get("REDIS_URL"))
    return nuk.write_db_env(app, env)


def purge_databases(app: str) -> None:
    """Drop an app's database/role and redis user, then forget its creds marker.

    Order matters: only remove the creds AFTER the drops succeed, so a failure
    (e.g. data stack down) leaves the DB still tracked rather than orphaned.

    Args:
        app: The app name.
    """
    nuk._safe_ident(app)
    env = nuk.read_db_env(app)
    if "DATABASE_URL" in env:
        nuk._psql(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608  # _lit-quoted
            f"WHERE datname = {_lit(app)} AND pid <> pg_backend_pid();"
        )
        nuk._psql(f'DROP DATABASE IF EXISTS "{app}";')  # noqa: S608  # app guarded by _safe_ident
        nuk._psql(f'DROP ROLE IF EXISTS "{app}";')  # noqa: S608  # app guarded by _safe_ident
    if "REDIS_URL" in env:
        nuk._redis_admin("ACL", "DELUSER", app)
        nuk._redis_admin("ACL", "SAVE")
    nuk._db_env_path(app).unlink(missing_ok=True)
