#!/usr/bin/env python3
"""nuk — minimal Kubernetes-shaped Docker Compose deployer.

Manifest (apiVersion: nuk/v1, kind: Deployment) describes one git repo with a
compose project, optional ingress hosts, and env files. State lives entirely in
/opt/nuklaut/ on the host; no daemon, no database.
"""
from __future__ import annotations
import argparse, os, re, secrets, shutil, subprocess, sys, textwrap
from pathlib import Path
from urllib.parse import urlparse
import yaml

__version__ = "0.0.0+dev"  # releases stamp the real version from the git tag (see .github/workflows/release.yml)

ROOT = Path("/opt/nuklaut")
DEPLOYS = ROOT / "deployments"
DYNAMIC = ROOT / "traefik" / "dynamic"
SECRETS = ROOT / "secrets"

# Shared data stack (files/docker-compose.data.yml). Apps reach these by their
# container names over the private `data` network.
PG_CONTAINER = "nuk-postgres"
REDIS_CONTAINER = "nuk-redis"


def sh(*cmd: str, cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def load(path: Path) -> dict:
    spec = yaml.safe_load(path.read_text())
    if spec.get("apiVersion") != "nuk/v1" or spec.get("kind") != "Deployment":
        sys.exit(f"{path}: not a nuk/v1 Deployment")
    return spec


def project_dir(name: str) -> Path:
    return DEPLOYS / name


def compose_args(name: str, spec: dict) -> list[str]:
    repo = project_dir(name) / "repo"
    cf = spec["spec"].get("compose", {}).get("file", "docker-compose.yml")
    override = project_dir(name) / "compose.override.yml"
    args = ["docker", "compose", "-p", name, "-f", str(repo / cf)]
    if override.exists():
        args += ["-f", str(override)]
    for envfile in spec["spec"].get("envFrom", []):
        ref = envfile.get("secretRef") if isinstance(envfile, dict) else envfile
        if ref and Path(ref).exists():
            args += ["--env-file", ref]
    return args


def resolve_env_from(spec: dict) -> list[str]:
    """Resolve `spec.envFrom[].secretRef` entries to existing file paths (same
    resolution `compose_args` uses for `--env-file`): an entry may be a dict
    with key `secretRef` or a bare string; only existing paths are kept."""
    refs = []
    for envfile in spec.get("envFrom", []):
        ref = envfile.get("secretRef") if isinstance(envfile, dict) else envfile
        if ref and Path(ref).exists():
            refs.append(ref)
    return refs


def build_override(name: str, ingress: list[dict], db_env: str | None = None,
                    env_from: list[str] | None = None) -> dict | None:
    """Compose override joining each ingress service to the shared edge network
    (Traefik ingress). Each ingress service also gets an `env_file` list so its
    container actually receives the requested secrets — `docker compose
    --env-file` only feeds ${VAR} interpolation in the compose file, it does NOT
    set container env, so this override is the only thing that does.

    `env_file` entries (in order) are: any `spec.envFrom[].secretRef` paths
    (env_from), then — when the deployment requested a database — the per-app
    creds file (db_env) last, so its generated DATABASE_URL / REDIS_URL win on
    key collisions. db_env is the 600 creds file, so its secret values never
    enter this (deploy-readable) override.

    The `data` network join remains gated on db_env only (unrelated to
    env_from). Note: env_file is only attached to INGRESS services, same as the
    existing db_env behaviour — acceptable for v1 / single-service apps."""
    env_from = env_from or []
    nets = ["edge", "data"] if db_env else ["edge"]
    env_files = [*env_from, *([db_env] if db_env else [])]
    services = {}
    for ing in ingress:
        svc: dict = {"networks": list(nets)}
        if env_files:
            svc["env_file"] = list(env_files)
        services[ing["service"]] = svc
    if not services:
        return None
    networks: dict = {"edge": {"external": True}}
    if db_env:
        networks["data"] = {"external": True}
    return {"services": services, "networks": networks}


def write_override(name: str, ingress: list[dict], db_env: str | None = None,
                    env_from: list[str] | None = None) -> None:
    doc = build_override(name, ingress, db_env, env_from)
    if doc is None:
        return
    (project_dir(name) / "compose.override.yml").write_text(yaml.safe_dump(doc))


def _rule(ing: dict) -> str:
    rule = f"Host(`{ing['host']}`)"
    if ing.get("path"):
        rule += f" && PathPrefix(`{ing['path']}`)"
    return rule


def build_ingress(name: str, ingress: list[dict]) -> dict | None:
    """Render the Traefik file-provider doc, or None to remove the dynamic file.

    Each entry needs host/service/port. Optional, all backward-compatible:
      path        adds PathPrefix(`<path>`) to the router rule
      stripPrefix strip `path` before proxying (needs path)
      priority    explicit router priority (Traefik else ranks by rule length)
      www         also answer www.<host> with a 301 to <host> (opt-in; apex only)
      auth        "oauth" -> gate via the oauth2-proxy GitHub forwardAuth chain
                  (needs an oauth2-proxy /oauth2/ route for <host>)
    """
    if not ingress:
        return None
    routers, services, middlewares = {}, {}, {}
    for i, ing in enumerate(ingress):
        rid = f"{name}-{i}"
        router = {
            "rule": _rule(ing),
            "entryPoints": ["websecure"],
            "service": rid,
            "tls": {"certResolver": "letsencrypt"},
        }
        mw = []
        # Opt-in GitHub-OAuth gate (oauth2-proxy forwardAuth) for internal apps
        # like nukview. Mirror the dashboard's [oauth-errors, oauth-auth] order:
        # errors (outer) catches the 401-403 the auth (inner) returns and serves
        # the sign-in page. Both middlewares live in global.yml; this host also
        # needs an oauth2-proxy /oauth2/ route (see docker-compose.traefik.yml).
        if ing.get("auth") == "oauth":
            mw += ["oauth-errors@file", "oauth-auth@file"]
        if ing.get("path") and ing.get("stripPrefix"):
            sid = f"{rid}-strip"
            middlewares[sid] = {"stripPrefix": {"prefixes": [ing["path"]]}}
            mw.append(sid)
        # Every app router inherits the controller-wide branded maintenance page:
        # 502-504 from the backend → the maintenance service (see global.yml). The
        # middleware is provider-qualified (@file) since it lives in global.yml.
        mw.append("maintenance-errors@file")
        router["middlewares"] = mw
        if "priority" in ing:
            router["priority"] = ing["priority"]
        routers[rid] = router
        services[rid] = {"loadBalancer": {"servers": [
            {"url": f"http://{name}-{ing['service']}-1:{ing['port']}"}
        ]}}
        if ing.get("www"):
            host = ing["host"]
            wid, rdid = f"{rid}-www", f"{rid}-www-redirect"
            middlewares[rdid] = {"redirectRegex": {
                "regex": rf"^https?://www\.{re.escape(host)}/(.*)",
                "replacement": f"https://{host}/${{1}}",
                "permanent": True,
            }}
            routers[wid] = {
                "rule": f"Host(`www.{host}`)",
                "entryPoints": ["websecure"],
                "service": rid,
                "middlewares": [rdid],
                "tls": {"certResolver": "letsencrypt"},
            }
    http = {"routers": routers, "services": services}
    if middlewares:
        http["middlewares"] = middlewares
    return {"http": http}


def write_ingress(name: str, ingress: list[dict]) -> None:
    target = DYNAMIC / f"{name}.yml"
    doc = build_ingress(name, ingress)
    if doc is None:
        target.unlink(missing_ok=True)
        return
    target.write_text(yaml.safe_dump(doc))


# --- shared databases (postgres + redis) -------------------------------------
# A deployment opts in via `spec.databases: {postgres: true, redis: true}`. nuk
# provisions a per-app Postgres role+database (pgvector enabled) and/or a per-app
# Redis ACL user against the shared data stack, generates credentials ONCE, and
# stores them in /opt/nuklaut/secrets/<app>-db.env (600). The generated override
# wires that file (env_file) + the data network onto the app's ingress services,
# so the container starts with DATABASE_URL / REDIS_URL set.
#
# Admin paths never need a TCP password: psql uses the container's local-socket
# trust; redis-cli reads REDIS_ADMIN_PASSWORD from the container's own env.

_IDENT = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")


def _safe_ident(name: str) -> str:
    """Guard the one thing SQL/ACL cannot parameterise: the identifier. Deployment
    names are DNS-ish already; anything else is rejected rather than quoted."""
    if not _IDENT.match(name):
        sys.exit(f"nuk: {name!r} is not a valid database identifier ([a-z][a-z0-9_-]*)")
    return name


def _lit(s: str) -> str:
    """A safely single-quoted SQL string literal (doubles embedded quotes)."""
    return "'" + s.replace("'", "''") + "'"


def _pw_from_url(url: str | None) -> str | None:
    return urlparse(url).password if url else None


def _chown_deploy(path: Path) -> None:
    """Make a freshly written secret deploy-owned so compose can read it whether
    nuk ran as root (deploy.sh) or as deploy (the CI runner)."""
    if os.geteuid() != 0:
        return
    import pwd
    try:
        u = pwd.getpwnam("deploy")
        os.chown(path, u.pw_uid, u.pw_gid)
    except KeyError:
        pass


def read_db_env(app: str) -> dict[str, str]:
    path = SECRETS / f"{app}-db.env"
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def write_db_env(app: str, env: dict[str, str]) -> str:
    SECRETS.mkdir(parents=True, exist_ok=True)
    path = SECRETS / f"{app}-db.env"
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()))
    path.chmod(0o600)
    _chown_deploy(path)
    return str(path)


def _psql(sql: str, db: str = "postgres") -> str:
    return subprocess.run(
        ["docker", "exec", "-i", PG_CONTAINER, "psql", "-U", "postgres",
         "-d", db, "-v", "ON_ERROR_STOP=1", "-tAqc", sql],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _redis_admin(*redis_args: str) -> str:
    # Auth as nukadmin using the password from the container's own env, so it
    # never lands on a host process-arg line.
    script = 'REDISCLI_AUTH="$REDIS_ADMIN_PASSWORD" exec redis-cli --user nukadmin "$@"'
    return subprocess.run(
        ["docker", "exec", REDIS_CONTAINER, "sh", "-c", script, "_", *redis_args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def ensure_postgres(app: str, prev_url: str | None, driver: str | None = None) -> str:
    """Idempotently create role + database (pgvector enabled) for `app`; return a
    DATABASE_URL. Re-uses the existing password so re-applies don't churn creds.
    `driver` picks the SQLAlchemy-style scheme suffix (e.g. "asyncpg" yields
    postgresql+asyncpg://); None yields the bare libpq postgresql:// URL."""
    if driver and not re.fullmatch(r"[a-z][a-z0-9]*", driver):
        sys.exit(f"nuk: invalid postgres driver {driver!r}")
    pw = _pw_from_url(prev_url) or secrets.token_urlsafe(24)
    _psql(f'DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {_lit(app)}) '
          f'THEN CREATE ROLE "{app}" LOGIN; END IF; END $$;')
    _psql(f'ALTER ROLE "{app}" WITH LOGIN PASSWORD {_lit(pw)};')
    if _psql(f"SELECT 1 FROM pg_database WHERE datname = {_lit(app)};") != "1":
        _psql(f'CREATE DATABASE "{app}" OWNER "{app}";')
    # Isolate: only the owner role may connect to this database.
    _psql(f'REVOKE CONNECT ON DATABASE "{app}" FROM PUBLIC;')
    _psql(f'GRANT CONNECT ON DATABASE "{app}" TO "{app}";')
    _psql("CREATE EXTENSION IF NOT EXISTS vector;", db=app)
    scheme = f"postgresql+{driver}" if driver else "postgresql"
    return f"{scheme}://{app}:{pw}@{PG_CONTAINER}:5432/{app}"


def ensure_redis(app: str, prev_url: str | None) -> str:
    """Idempotently (re-)create a per-app Redis ACL user limited to its own key
    prefix + channels, with dangerous commands removed (no FLUSHALL on the shared
    instance). Persist to the aclfile. Return a REDIS_URL."""
    pw = _pw_from_url(prev_url) or secrets.token_urlsafe(24)
    _redis_admin("ACL", "SETUSER", app, "reset", "on", f">{pw}",
                 f"~{app}:*", f"&{app}:*", "+@all", "-@dangerous")
    _redis_admin("ACL", "SAVE")
    return f"redis://{app}:{pw}@{REDIS_CONTAINER}:6379/0"


def provision_databases(app: str, databases: dict) -> str | None:
    """Provision the databases a manifest requested; return the path to the creds
    env-file the override should inject, or None when none are requested."""
    pg = databases.get("postgres")
    want_pg = bool(pg)
    want_redis = bool(databases.get("redis"))
    if not (want_pg or want_redis):
        return None
    _safe_ident(app)
    prev = read_db_env(app)
    env: dict[str, str] = {}
    if want_pg:
        driver = pg.get("driver") if isinstance(pg, dict) else None
        env["DATABASE_URL"] = ensure_postgres(app, prev.get("DATABASE_URL"), driver)
    if want_redis:
        env["REDIS_URL"] = ensure_redis(app, prev.get("REDIS_URL"))
    return write_db_env(app, env)


def purge_databases(app: str) -> None:
    """Drop an app's database/role and redis user, then forget its creds marker.
    Order matters: only remove the creds AFTER the drops succeed, so a failure
    (e.g. data stack down) leaves the DB still tracked rather than orphaned."""
    _safe_ident(app)
    env = read_db_env(app)
    if "DATABASE_URL" in env:
        _psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
              f"WHERE datname = {_lit(app)} AND pid <> pg_backend_pid();")
        _psql(f'DROP DATABASE IF EXISTS "{app}";')
        _psql(f'DROP ROLE IF EXISTS "{app}";')
    if "REDIS_URL" in env:
        _redis_admin("ACL", "DELUSER", app)
        _redis_admin("ACL", "SAVE")
    (SECRETS / f"{app}-db.env").unlink(missing_ok=True)


def cmd_apply(args) -> None:
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    DEPLOYS.mkdir(parents=True, exist_ok=True)
    spec = load(Path(args.manifest))
    name = spec["metadata"]["name"]
    src = spec["spec"].get("source", {})
    pdir = project_dir(name)
    pdir.mkdir(parents=True, exist_ok=True)
    repo = pdir / "repo"
    if args.repo_path:
        # Workflow-managed: caller already has a checkout; mirror it in place.
        # rsync -a --delete keeps repo/ identical to the source tree.
        sh("rsync", "-a", "--delete", "--exclude", ".git", f"{Path(args.repo_path).resolve()}/", str(repo) + "/")
    elif "repo" in src:
        branch = src.get("branch", "main")
        if not (repo / ".git").exists():
            shutil.rmtree(repo, ignore_errors=True)
            sh("git", "clone", "--branch", branch, src["repo"], str(repo))
        else:
            sh("git", "-C", str(repo), "fetch", "--quiet")
            sh("git", "-C", str(repo), "checkout", branch)
            sh("git", "-C", str(repo), "pull", "--ff-only", "--quiet")
    else:
        sys.exit(f"{args.manifest}: spec.source.repo is required unless --repo-path is given")
    ingress = spec["spec"].get("ingress", []) or []
    db_env = provision_databases(name, spec["spec"].get("databases") or {})
    if db_env and not ingress:
        print(f"{name}: databases provisioned but no ingress service to attach "
              f"them to — DATABASE_URL/REDIS_URL won't be injected. Add an ingress entry.")
    env_from = resolve_env_from(spec["spec"])
    if env_from and not ingress:
        print(f"{name}: spec.envFrom secrets resolved but no ingress service to "
              f"attach them to — they won't be injected. Add an ingress entry.")
    write_override(name, ingress, db_env, env_from)
    write_ingress(name, ingress)
    shutil.copy(args.manifest, pdir / "manifest.yml")
    # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
    # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
    # whose image id changed.
    sh(*compose_args(name, spec), "up", "-d")


def cmd_get(_args) -> None:
    if not DEPLOYS.exists():
        return
    for pdir in sorted(p for p in DEPLOYS.iterdir() if p.is_dir()):
        manifest = pdir / "manifest.yml"
        if not manifest.exists():
            continue
        spec = load(manifest)
        hosts = ",".join(i["host"] for i in spec["spec"].get("ingress", []) or [])
        ps = subprocess.run(
            ["docker", "compose", "-p", pdir.name, "ps", "--format", "{{.State}}"],
            capture_output=True, text=True,
        ).stdout.strip().replace("\n", ",") or "-"
        print(f"{pdir.name:24} {ps:32} {hosts}")


def cmd_logs(args) -> None:
    sh(*compose_args(args.name, load(project_dir(args.name) / "manifest.yml")),
       "logs", "-f")


def cmd_rollout(args) -> None:
    spec = load(project_dir(args.name) / "manifest.yml")
    repo = project_dir(args.name) / "repo"
    if (repo / ".git").exists():
        sh("git", "-C", str(repo), "pull", "--ff-only")
    # else: workflow-managed deployment — re-trigger the workflow to update the tree.
    sh(*compose_args(args.name, spec), "pull")
    sh(*compose_args(args.name, spec), "up", "-d")


def cmd_delete(args) -> None:
    pdir = project_dir(args.name)
    if (pdir / "manifest.yml").exists():
        spec = load(pdir / "manifest.yml")
        subprocess.run([*compose_args(args.name, spec), "down", "-v"], check=False)
    (DYNAMIC / f"{args.name}.yml").unlink(missing_ok=True)
    shutil.rmtree(pdir, ignore_errors=True)
    # The app's database is kept by default — its creds file (in SECRETS, not
    # pdir) survives rmtree and keeps nuk aware of it (see `nuk db ls`). --purge
    # is the only path that destroys data.
    if getattr(args, "purge", False):
        purge_databases(args.name)
    elif (SECRETS / f"{args.name}-db.env").exists():
        print(f"{args.name}: database retained. `nuk db ls` to view, "
              f"`nuk db purge {args.name}` to drop it.")


def cmd_db_ls(_args) -> None:
    if not SECRETS.exists():
        return
    for f in sorted(SECRETS.glob("*-db.env")):
        app = f.name[: -len("-db.env")]
        env = read_db_env(app)
        kinds = ",".join(
            k for k, present in
            (("postgres", "DATABASE_URL" in env), ("redis", "REDIS_URL" in env))
            if present
        ) or "-"
        live = (DEPLOYS / app / "manifest.yml").exists()
        status = "deployed" if live else "RETAINED (no deployment — nuk db purge to drop)"
        print(f"{app:24} {kinds:16} {status}")


def cmd_db_purge(args) -> None:
    purge_databases(args.name)
    print(f"{args.name}: database purged.")


def main() -> None:
    p = argparse.ArgumentParser(prog="nuk", formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Manifest (apiVersion: nuk/v1, kind: Deployment):
          metadata.name, spec.source.{repo,branch}, spec.compose.file,
          spec.ingress[].{host,service,port}, spec.envFrom[].secretRef
          spec.ingress[] also takes optional: path (PathPrefix), stripPrefix,
            priority, www (301 www.<host> -> <host>; apex domains only),
            auth ("oauth" -> GitHub oauth2-proxy gate)
          spec.envFrom[].secretRef -> existing env files injected into each
            ingress service's container env via the compose override (and also
            passed to `docker compose --env-file` for ${VAR} interpolation).
          spec.databases: {postgres: true, redis: true} -> per-app DB on the
            shared data stack; injects DATABASE_URL / REDIS_URL into the
            ingress service(s).
        """))
    p.add_argument("--version", action="version", version=f"nuk {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list deployments (alias: get, ls)").set_defaults(fn=cmd_get)
    sub.add_parser("get", help="alias for list").set_defaults(fn=cmd_get)
    sub.add_parser("ls", help="alias for list").set_defaults(fn=cmd_get)
    ap = sub.add_parser("apply", help="create or update a deployment from a manifest")
    ap.add_argument("manifest")
    ap.add_argument("--repo-path", default=None,
                    help="local path to use instead of cloning spec.source.repo "
                         "(for workflow-driven deploys where the runner already has a checkout)")
    ap.set_defaults(fn=cmd_apply)
    for name, fn, helptext in [
        ("logs", cmd_logs, "follow compose logs for a deployment"),
        ("rollout", cmd_rollout, "git pull + compose pull + up -d"),
    ]:
        s = sub.add_parser(name, help=helptext); s.add_argument("name"); s.set_defaults(fn=fn)
    dl = sub.add_parser("delete", help="tear down a deployment (keeps its database)")
    dl.add_argument("name")
    dl.add_argument("--purge", action="store_true",
                    help="also drop the app's postgres db/role + redis user (DESTROYS DATA)")
    dl.set_defaults(fn=cmd_delete)
    dbp = sub.add_parser("db", help="inspect/manage app databases (shared postgres/redis)")
    dbsub = dbp.add_subparsers(dest="dbcmd", required=True)
    dbsub.add_parser("ls", help="list managed databases; flags retained ones with no deployment").set_defaults(fn=cmd_db_ls)
    dbpurge = dbsub.add_parser("purge", help="drop a retained app's database + creds")
    dbpurge.add_argument("name"); dbpurge.set_defaults(fn=cmd_db_purge)
    args = p.parse_args()
    if not ROOT.exists():
        sys.exit(
            f"nuk: {ROOT} does not exist — nuk runs on the controller, "
            "not your workstation. Use: ./deploy.sh nuk " + args.cmd
        )
    args.fn(args)


if __name__ == "__main__":
    main()
