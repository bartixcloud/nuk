#!/usr/bin/env python3
"""nuk — minimal Kubernetes-shaped Docker Compose deployer.

Manifest (apiVersion: nuk/v1, kind: Deployment) describes one git repo with a
compose project, optional ingress hosts, and env files. State lives entirely in
/opt/nuklaut/ on the host; no daemon, no database.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
import sys
import urllib.request
from pathlib import Path
from typing import Annotated, Literal, cast
from urllib.parse import urlparse

import typer
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    model_validator,
)

__version__ = "0.11.0"  # bumped on release by .github/workflows/release.yml

ROOT = Path("/opt/nuklaut")
DEPLOYS = ROOT / "deployments"
DYNAMIC = ROOT / "traefik" / "dynamic"
SECRETS = ROOT / "secrets"

# Shared data stack — owned, reproducible source vendored at
# files/docker-compose.data.yml (bring it up once on the controller). Apps reach
# these by their container names over the private `data` network. provision_*
# preflights both containers (see preflight_data_stack) before any docker exec.
PG_CONTAINER = "nuk-postgres"
REDIS_CONTAINER = "nuk-redis"

# nuk distributes as a normal Python package: run ephemerally with
#   uvx --from git+https://github.com/astrojones/nuk@<ref> nuk ...
# or install/upgrade a pinned copy with `nuk update` (→ uv tool install --from …).
NUK_REPO = "astrojones/nuk"
NUK_GIT = f"git+https://github.com/{NUK_REPO}"


# --- manifest models ----------------------------------------------------------
# Typed view of the nuk/v1 manifest. Validation happens once, at the load()
# boundary; the render/compose functions below stay dict-in/dict-out because
# their YAML output is an external wire contract (Traefik + docker-compose) that
# must not shift. extra="ignore" (pydantic's default) so a real manifest with a
# field nuk does not model still validates rather than killing a live deploy.


class _NullTolerant(BaseModel):
    """Base for manifest blocks that treat a null-valued YAML key as absent.

    A bare YAML key (`ingress:`) parses to None; the original CLI defended every
    optional field with `or []`/`or {}`, so such manifests are valid in the wild
    (workflow deploys ship bare `source:`). Dropping None-valued keys before
    validation lets the field defaults engage instead of failing a strongly-typed
    field — keeping the fields non-Optional at the boundary.
    """

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v is not None}
        return data


class Source(BaseModel):
    """`spec.source` — the git repo and branch to deploy."""

    repo: str | None = None
    branch: str = "main"


class Compose(BaseModel):
    """`spec.compose` — path to the compose file inside the repo."""

    file: str = "docker-compose.yml"


class Ingress(BaseModel):
    """One `spec.ingress[]` entry — a single Traefik router/service."""

    model_config = ConfigDict(populate_by_name=True)

    host: str
    service: str
    port: int
    path: str | None = None
    strip_prefix: bool = Field(default=False, alias="stripPrefix")
    priority: int | None = None
    www: bool = False
    auth: str | None = None


class EnvFrom(BaseModel):
    """One `spec.envFrom[]` entry — a secret env-file reference."""

    model_config = ConfigDict(populate_by_name=True)

    secret_ref: str | None = Field(default=None, alias="secretRef")


class Postgres(BaseModel):
    """`spec.databases.postgres` object form — picks the URL scheme driver."""

    driver: str | None = None


class Databases(_NullTolerant):
    """`spec.databases` — opt-in per-app postgres/redis on the shared stack.

    By default the generated DATABASE_URL / REDIS_URL are injected into the
    ingress service(s). `attachTo` overrides that target list (e.g. to reach a
    worker that has no ingress); `attachAll` injects into every compose service.
    """

    model_config = ConfigDict(populate_by_name=True)

    postgres: bool | Postgres = False
    redis: bool = False
    attach_to: list[str] = Field(default=[], alias="attachTo")
    attach_all: bool = Field(default=False, alias="attachAll")


class Spec(_NullTolerant):
    """The manifest `spec` block."""

    model_config = ConfigDict(populate_by_name=True)

    source: Source = Source()
    compose: Compose = Compose()
    ingress: list[Ingress] = []
    env_from: list[EnvFrom] = Field(default=[], alias="envFrom")
    databases: Databases = Databases()


class Metadata(BaseModel):
    """The manifest `metadata` block."""

    name: str


class Manifest(_NullTolerant):
    """A validated nuk/v1 Deployment manifest.

    Carries the typed view used by the command layer plus the raw parsed dict
    (`raw`) handed unchanged to the wire-contract render functions, so their
    YAML output never shifts shape.
    """

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nuk/v1"] = Field(alias="apiVersion")
    kind: Literal["Deployment"]
    metadata: Metadata
    spec: Spec = Spec()

    _raw: dict = PrivateAttr(default_factory=dict)

    @property
    def raw(self) -> dict:
        """The original parsed manifest dict (wire-contract input)."""
        return self._raw


# --- org capability manifest (nukorg/v1) --------------------------------------
# One org's declarative facility choices, read by BOTH the core bootstrap (to
# BUILD the platform) and the deploy plugin (to OPERATE it). Kept flat (not
# spec-nested like nuk/v1) because it is human-edited and read key-by-key by
# shell (`nuk org get facilities.auth`); dotted paths use the YAML alias names.


class OrgData(BaseModel):
    """`facilities.data` — which shared data services this org runs."""

    postgres: bool = True
    redis: bool = True


class Facilities(BaseModel):
    """`facilities` — this org's variant of each pluggable platform capability."""

    model_config = ConfigDict(populate_by_name=True)

    dns: Literal["wildcard", "manual"]
    tls: Literal["dns01", "http01"]
    dns_provider: str | None = Field(default=None, alias="dnsProvider")
    secrets: Literal["sops", "generate", "ci-inject"]
    auth: Literal["basic", "oauth2-proxy", "authentik"]
    runners: Literal["ephemeral", "persistent"]
    data: OrgData = OrgData()

    @model_validator(mode="after")
    def _check_dns_tls(self) -> Facilities:
        """Enforce the DNS/TLS coupling that wildcard certs + DNS-01 require.

        Raises:
            ValueError: If wildcard DNS is paired with a non-DNS-01 challenge, or
                a DNS-01 challenge omits its provider.
        """
        if self.dns == "wildcard" and self.tls != "dns01":
            msg = "facilities.dns=wildcard requires facilities.tls=dns01 (wildcard needs DNS-01)"
            raise ValueError(msg)
        if self.tls == "dns01" and not self.dns_provider:
            msg = "facilities.tls=dns01 requires facilities.dnsProvider"
            raise ValueError(msg)
        return self


class Controller(BaseModel):
    """`controller` — how this org's controller host is provisioned + reached."""

    model_config = ConfigDict(populate_by_name=True)

    hostname: str
    provisioner: Literal["terraform", "manual", "ansible"]
    deploy_mode: Literal["ssh", "local"] = Field(default="ssh", alias="deployMode")


class Pins(BaseModel):
    """`pins` — pinned generic-core + nuk versions this org runs (owner/repo@ref)."""

    core: str
    nuk: str | None = None


class Org(BaseModel):
    """A validated nukorg/v1 Org manifest (`<org>/infra/nuklaut.org.yml`)."""

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nukorg/v1"] = Field(alias="apiVersion")
    kind: Literal["Org"]
    metadata: Metadata
    domain: str
    acme_email: str = Field(alias="acmeEmail")
    controller: Controller
    facilities: Facilities
    overlays: list[str] = []
    pins: Pins


def sh(*cmd: str, cwd: Path | None = None) -> None:
    """Run a command, raising on non-zero exit."""
    subprocess.run(cmd, cwd=cwd, check=True)  # noqa: S603  # fixed argv, no shell


def load(path: Path) -> Manifest:
    """Parse and validate a manifest file into a `Manifest`.

    Args:
        path: Path to the manifest YAML.

    Returns:
        The validated manifest, carrying the raw parsed dict for the render
        functions.

    Raises:
        SystemExit: If the document is not a valid nuk/v1 Deployment.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        manifest = Manifest.model_validate(raw)
    except ValidationError:
        sys.exit(f"{path}: not a nuk/v1 Deployment")
    manifest._raw = raw  # noqa: SLF001  # stash wire-contract input on its own model
    return manifest


def load_org(path: Path) -> Org:
    """Parse and validate a nukorg/v1 Org manifest file.

    Args:
        path: Path to the org manifest YAML (`nuklaut.org.yml`).

    Returns:
        The validated Org.

    Raises:
        SystemExit: If the file is unreadable or not a valid nukorg/v1 Org.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        sys.exit(f"{path}: {e}")
    try:
        return Org.model_validate(raw)
    except ValidationError as e:
        sys.exit(f"{path}: invalid nukorg/v1 Org\n{e}")


def org_get(org: Org, dotted: str) -> object:
    """Return a value from an Org by dotted alias path (e.g. `facilities.auth`).

    Args:
        org: The validated Org.
        dotted: Dot-separated key path using the manifest's YAML (alias) names.

    Returns:
        The value at that path (scalar, list, or dict).

    Raises:
        SystemExit: If any path segment is missing.
    """
    node: object = org.model_dump(by_alias=True)
    for part in dotted.split("."):
        if not isinstance(node, dict):
            sys.exit(f"nuk org get: no such key: {dotted}")
        current = cast("dict[str, object]", node)
        if part not in current:
            sys.exit(f"nuk org get: no such key: {dotted}")
        node = current[part]
    return node


def project_dir(name: str) -> Path:
    """Return the on-disk deployment directory for an app."""
    return DEPLOYS / name


def github_url(remote: str) -> str | None:
    """Normalise a git remote (ssh or https) to its github.com web URL, or None."""
    remote = remote.strip()
    m = re.match(r"git@github\.com:(.+?)(?:\.git)?$", remote) or re.match(
        r"https?://github\.com/(.+?)(?:\.git)?$", remote
    )
    return f"https://github.com/{m.group(1)}" if m else None


def git_origin(repo_path: str) -> str | None:
    """github.com web URL for repo_path's origin remote, or None if unavailable."""
    try:
        out = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["git", "-C", repo_path, "config", "--get", "remote.origin.url"],  # noqa: S607  # git on PATH
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    return github_url(out)


def origin_org(repo_path: str = ".") -> str | None:
    """The GitHub owner (org) of repo_path's origin remote, or None.

    The org's config lives at `<owner>/infra`; the deploy plugin resolves which
    org to operate on from the app repo it is invoked in.

    Args:
        repo_path: Path to the git checkout (default: cwd).

    Returns:
        The GitHub owner, or None if there is no github origin.
    """
    url = git_origin(repo_path)
    if not url:
        return None
    m = re.match(r"https://github\.com/([^/]+)/", f"{url}/")
    return m.group(1) if m else None


def persist_manifest(spec: dict, src_path: Path, dest: Path, repo_path: str | None) -> None:
    """Write the deployment manifest to the controller for nukview to read.

    Copied verbatim, except: when applied with --repo-path and the manifest did
    not declare spec.source.repo, stamp it from the checkout's git origin. This
    gives nukview a repo link for workflow-deployed apps, whose CI passes
    --repo-path and whose manifests usually omit source.repo.

    Args:
        spec: The raw parsed manifest dict.
        src_path: Path the manifest was read from.
        dest: Destination path on the controller.
        repo_path: The --repo-path checkout, if any.
    """
    src = spec["spec"].get("source") or {}
    origin = git_origin(repo_path) if repo_path else None
    if origin and not src.get("repo"):
        spec["spec"]["source"] = {**src, "repo": origin}
        dest.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    else:
        shutil.copy(src_path, dest)


def compose_args(name: str, spec: dict) -> list[str]:
    """Build the `docker compose` base argv for an app from its raw spec."""
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
    """Resolve `spec.envFrom[].secretRef` entries to existing file paths.

    Uses the same resolution `compose_args` applies for `--env-file`: an entry
    may be a dict with key `secretRef` or a bare string; only existing paths are
    kept.

    Args:
        spec: The raw `spec` dict.

    Returns:
        The existing secret-file paths, in manifest order.
    """
    refs = []
    for envfile in spec.get("envFrom", []):
        ref = envfile.get("secretRef") if isinstance(envfile, dict) else envfile
        if ref and Path(ref).exists():
            refs.append(ref)
    return refs


def build_override(
    name: str,  # noqa: ARG001  # kept for signature stability (frozen wire-contract API / tests)
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
) -> dict | None:
    """Compose override wiring services to the shared edge/data networks + secrets.

    Each service gets an `env_file` list so its container actually receives the
    requested secrets — `docker compose --env-file` only feeds ${VAR}
    interpolation in the compose file, it does NOT set container env, so this
    override is the only thing that does.

    Two overlapping roles a service can have:
      * INGRESS service (`spec.ingress[].service`) — joins the `edge` network.
      * DB service (`db_services`) — joins the `data` network and gets the
        per-app creds file (db_env) appended to its env_file, so DATABASE_URL /
        REDIS_URL reach it. `db_services` defaults to the ingress services
        (backward-compatible), but `databases.attachTo` / `attachAll` can route
        the creds to a worker that has no ingress (see resolve_db_services).

    `env_file` entries (in order) are the `spec.envFrom[].secretRef` paths
    (env_from), then — for a DB service — the per-app creds file (db_env) last,
    so its generated URLs win on key collisions. db_env is the 600 creds file,
    so its secret values never enter this (deploy-readable) override.

    Args:
        name: The deployment name (unused; kept for signature stability).
        ingress: The raw `spec.ingress[]` entries.
        db_env: Path to the per-app creds env-file, if a database was requested.
        env_from: Resolved `spec.envFrom` secret-file paths.
        db_services: Services that should receive the db creds + data network;
            None means "the ingress services" (the legacy default).

    Returns:
        The override doc, or None when no service needs any wiring.
    """
    env_from = env_from or []
    ingress_services = [ing["service"] for ing in ingress]
    db_targets = (list(ingress_services) if db_env else []) if db_services is None else db_services
    db_set = set(db_targets) if db_env else set()
    # Ingress order first, then any db-only (non-ingress) services, deduped.
    ordered = list(dict.fromkeys([*ingress_services, *db_targets]))
    services: dict = {}
    for svc_name in ordered:
        is_ingress = svc_name in ingress_services
        is_db = svc_name in db_set
        nets = (["edge"] if is_ingress else []) + (["data"] if is_db else [])
        env_files = [*env_from, *([db_env] if is_db else [])]
        svc: dict = {"networks": nets}
        if env_files:
            svc["env_file"] = env_files
        services[svc_name] = svc
    if not services:
        return None
    networks: dict = {}
    if any(s in ingress_services for s in services):
        networks["edge"] = {"external": True}
    if any(s in db_set for s in services):
        networks["data"] = {"external": True}
    return {"services": services, "networks": networks}


def write_override(
    name: str,
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
) -> None:
    """Render and write `compose.override.yml` for an app (no-op when empty)."""
    doc = build_override(name, ingress, db_env, env_from, db_services)
    if doc is None:
        return
    (project_dir(name) / "compose.override.yml").write_text(yaml.safe_dump(doc))


def compose_service_names(name: str, raw: dict) -> list[str]:
    """Return the service names declared in an app's checked-out compose file.

    Used by `attachAll` to enumerate every service that should receive the DB
    creds. Returns an empty list when the compose file is absent or has no
    services (the caller then injects nowhere rather than failing the apply).

    Args:
        name: The deployment name (locates `<project_dir>/repo`).
        raw: The raw manifest dict (for `spec.compose.file`).

    Returns:
        The compose `services` keys, in file order.
    """
    cf = raw["spec"].get("compose", {}).get("file", "docker-compose.yml")
    path = project_dir(name) / "repo" / cf
    if not path.exists():
        return []
    doc = yaml.safe_load(path.read_text()) or {}
    return list((doc.get("services") or {}).keys())


def resolve_db_services(name: str, raw: dict, db_env: str | None) -> list[str]:
    """Resolve which compose services the provisioned DB creds attach to.

    Precedence: `attachAll` (every compose service) > `attachTo` (explicit list)
    > the ingress services (legacy default). Empty when no database was
    provisioned.

    Args:
        name: The deployment name.
        raw: The raw manifest dict.
        db_env: The provisioned creds path, or None when no DB was requested.

    Returns:
        The service names to inject DATABASE_URL / REDIS_URL into.
    """
    if not db_env:
        return []
    databases = raw["spec"].get("databases") or {}
    if databases.get("attachAll"):
        return compose_service_names(name, raw)
    attach_to = databases.get("attachTo")
    if attach_to:
        return list(attach_to)
    return [ing["service"] for ing in raw["spec"].get("ingress", []) or []]


def _rule(ing: dict) -> str:
    """Build the Traefik router rule for one ingress entry."""
    rule = f"Host(`{ing['host']}`)"
    if ing.get("path"):
        rule += f" && PathPrefix(`{ing['path']}`)"
    return rule


def build_ingress(name: str, ingress: list[dict]) -> dict | None:  # noqa: C901, PLR0912  # one router-build loop; clean extraction would obscure the per-field ordering
    """Render the Traefik file-provider doc, or None to remove the dynamic file.

    Each entry needs host/service/port. Optional, all backward-compatible:
      path        adds PathPrefix(`<path>`) to the router rule
      stripPrefix strip `path` before proxying (needs path)
      priority    explicit router priority (Traefik else ranks by rule length)
      www         also answer www.<host> with a 301 to <host> (opt-in; apex only)
      auth        "oauth" -> gate via the oauth2-proxy GitHub forwardAuth chain
                  (needs an oauth2-proxy /oauth2/ route for <host>)
                  "basic" -> HTTP Basic Auth (auth@file middleware from global.yml)

    Args:
        name: The deployment name, used to prefix router/service ids.
        ingress: The raw `spec.ingress[]` entries.

    Returns:
        The Traefik dynamic doc, or None when there is no ingress.
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
        elif ing.get("auth") == "basic":
            mw += ["auth@file"]
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
        services[rid] = {
            "loadBalancer": {
                "servers": [{"url": f"http://{name}-{ing['service']}-1:{ing['port']}"}]
            }
        }
        if ing.get("www"):
            host = ing["host"]
            wid, rdid = f"{rid}-www", f"{rid}-www-redirect"
            middlewares[rdid] = {
                "redirectRegex": {
                    "regex": rf"^https?://www\.{re.escape(host)}/(.*)",
                    "replacement": f"https://{host}/${{1}}",
                    "permanent": True,
                }
            }
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
    """Render and write the Traefik dynamic file for an app (removes it if empty)."""
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
    """Guard the one thing SQL/ACL cannot parameterise: the identifier.

    Deployment names are DNS-ish already; anything else is rejected rather than
    quoted.

    Args:
        name: The candidate identifier.

    Returns:
        The identifier, unchanged, when valid.

    Raises:
        SystemExit: When the identifier does not match `[a-z][a-z0-9_-]*`.
    """
    if not _IDENT.match(name):
        sys.exit(f"nuk: {name!r} is not a valid database identifier ([a-z][a-z0-9_-]*)")
    return name


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


def _chown_deploy(path: Path) -> None:
    """Make a freshly written secret deploy-owned so compose can read it.

    Applies whether nuk ran as root (deploy.sh) or as deploy (the CI runner).

    Args:
        path: The secret file to chown.
    """
    if os.geteuid() != 0:
        return
    import pwd

    try:
        u = pwd.getpwnam("deploy")
        os.chown(path, u.pw_uid, u.pw_gid)
    except KeyError:
        pass


def read_db_env(app: str) -> dict[str, str]:
    """Read an app's persisted DB creds env-file into a dict (empty if absent)."""
    path = SECRETS / f"{app}-db.env"
    out: dict[str, str] = {}
    if path.exists():
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return out


def write_db_env(app: str, env: dict[str, str]) -> str:
    """Write an app's DB creds env-file (600, deploy-owned); return its path."""
    SECRETS.mkdir(parents=True, exist_ok=True)
    path = SECRETS / f"{app}-db.env"
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
            PG_CONTAINER,
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
        ["docker", "exec", REDIS_CONTAINER, "sh", "-c", script, "_", *redis_args],  # noqa: S607  # docker on PATH
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
        SystemExit: When a required container is missing/unhealthy, pgvector is
            unavailable, or the redis `nukadmin` user cannot be reached.
    """
    if want_pg:
        _require_container(PG_CONTAINER, "postgres")
        if _psql("SELECT 1 FROM pg_available_extensions WHERE name = 'vector';") != "1":
            sys.exit(
                f"nuk: pgvector not available in {PG_CONTAINER!r} — the data stack image "
                f"must provide the 'vector' extension (use pgvector/pgvector)"
            )
    if want_redis:
        _require_container(REDIS_CONTAINER, "redis")
        try:
            whoami = _redis_admin("ACL", "WHOAMI")
        except subprocess.CalledProcessError:
            whoami = ""
        if whoami != "nukadmin":
            sys.exit(
                f"nuk: redis 'nukadmin' admin user not reachable in "
                f"{REDIS_CONTAINER!r} — {_DATA_STACK_HINT}"
            )


def _require_container(container: str, label: str) -> None:
    """Abort with an actionable message unless `container` exists and is healthy."""
    exists, healthy = _container_state(container)
    if not exists:
        sys.exit(f"nuk: shared {label} container {container!r} not found — {_DATA_STACK_HINT}")
    if not healthy:
        sys.exit(f"nuk: shared {label} container {container!r} not healthy — {_DATA_STACK_HINT}")


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
        SystemExit: When `driver` is not a lowercase token.
    """
    if driver and not re.fullmatch(r"[a-z][a-z0-9]*", driver):
        sys.exit(f"nuk: invalid postgres driver {driver!r}")
    pw = _pw_from_url(prev_url) or secrets.token_urlsafe(24)
    _psql(
        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = {_lit(app)}) "
        f'THEN CREATE ROLE "{app}" LOGIN; END IF; END $$;'  # noqa: S608  # app guarded by _safe_ident
    )
    _psql(f'ALTER ROLE "{app}" WITH LOGIN PASSWORD {_lit(pw)};')  # noqa: S608  # app/pw guarded
    if _psql(f"SELECT 1 FROM pg_database WHERE datname = {_lit(app)};") != "1":  # noqa: S608  # _lit-quoted
        _psql(f'CREATE DATABASE "{app}" OWNER "{app}";')  # noqa: S608  # app guarded by _safe_ident
    # Isolate: only the owner role may connect to this database.
    _psql(f'REVOKE CONNECT ON DATABASE "{app}" FROM PUBLIC;')  # noqa: S608  # app guarded
    _psql(f'GRANT CONNECT ON DATABASE "{app}" TO "{app}";')  # noqa: S608  # app guarded
    _psql("CREATE EXTENSION IF NOT EXISTS vector;", db=app)
    scheme = f"postgresql+{driver}" if driver else "postgresql"
    return f"{scheme}://{app}:{pw}@{PG_CONTAINER}:5432/{app}"


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
    pw = _pw_from_url(prev_url) or secrets.token_urlsafe(24)
    _redis_admin(
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
    _redis_admin("ACL", "SAVE")
    return f"redis://{app}:{pw}@{REDIS_CONTAINER}:6379/0"


def provision_databases(app: str, databases: dict) -> str | None:
    """Provision the databases a manifest requested.

    Args:
        app: The app name.
        databases: The raw `spec.databases` dict.

    Returns:
        The path to the creds env-file the override should inject, or None when
        no databases are requested.
    """
    pg = databases.get("postgres")
    want_pg = bool(pg)
    want_redis = bool(databases.get("redis"))
    if not (want_pg or want_redis):
        return None
    _safe_ident(app)
    preflight_data_stack(want_pg, want_redis)
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
    (e.g. data stack down) leaves the DB still tracked rather than orphaned.

    Args:
        app: The app name.
    """
    _safe_ident(app)
    env = read_db_env(app)
    if "DATABASE_URL" in env:
        _psql(
            f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608  # _lit-quoted
            f"WHERE datname = {_lit(app)} AND pid <> pg_backend_pid();"
        )
        _psql(f'DROP DATABASE IF EXISTS "{app}";')  # noqa: S608  # app guarded by _safe_ident
        _psql(f'DROP ROLE IF EXISTS "{app}";')  # noqa: S608  # app guarded by _safe_ident
    if "REDIS_URL" in env:
        _redis_admin("ACL", "DELUSER", app)
        _redis_admin("ACL", "SAVE")
    (SECRETS / f"{app}-db.env").unlink(missing_ok=True)


# --- command layer ------------------------------------------------------------
# Commands read typed scalars off the validated Manifest but pass its raw dict
# (manifest.raw / manifest.raw["spec"]) to the wire-contract render functions.


def cmd_apply(manifest_path: Path, repo_path: str | None) -> None:  # noqa: C901, PLR0912  # linear apply pipeline; splitting it would scatter the reconcile order
    """Create or update a deployment from a manifest."""
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    DEPLOYS.mkdir(parents=True, exist_ok=True)
    manifest = load(manifest_path)
    raw = manifest.raw
    name = manifest.metadata.name
    source = manifest.spec.source
    pdir = project_dir(name)
    pdir.mkdir(parents=True, exist_ok=True)
    repo = pdir / "repo"
    if repo_path:
        # Workflow-managed: caller already has a checkout; mirror it in place.
        # rsync -a --delete keeps repo/ identical to the source tree.
        sh(
            "rsync",
            "-a",
            "--delete",
            "--exclude",
            ".git",
            f"{Path(repo_path).resolve()}/",
            str(repo) + "/",
        )
    elif source.repo:
        branch = source.branch
        if not (repo / ".git").exists():
            shutil.rmtree(repo, ignore_errors=True)
            sh("git", "clone", "--branch", branch, source.repo, str(repo))
        else:
            sh("git", "-C", str(repo), "fetch", "--quiet")
            sh("git", "-C", str(repo), "checkout", branch)
            sh("git", "-C", str(repo), "pull", "--ff-only", "--quiet")
    else:
        sys.exit(f"{manifest_path}: spec.source.repo is required unless --repo-path is given")
    ingress = raw["spec"].get("ingress", []) or []
    db_env = provision_databases(name, raw["spec"].get("databases") or {})
    db_services = resolve_db_services(name, raw, db_env)
    if db_env and not db_services:
        print(
            f"{name}: databases provisioned but no service to attach them to — "
            f"DATABASE_URL/REDIS_URL won't be injected. Add an ingress entry, or set "
            f"spec.databases.attachTo / attachAll to target a worker."
        )
    env_from = resolve_env_from(raw["spec"])
    if env_from and not ingress:
        print(
            f"{name}: spec.envFrom secrets resolved but no ingress service to "
            f"attach them to — they won't be injected. Add an ingress entry."
        )
    write_override(name, ingress, db_env, env_from, db_services)
    write_ingress(name, ingress)
    persist_manifest(raw, manifest_path, pdir / "manifest.yml", repo_path)
    # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
    # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
    # whose image id changed.
    sh(*compose_args(name, raw), "up", "-d")


def cmd_get() -> None:
    """List deployments with their container state and ingress hosts."""
    if not DEPLOYS.exists():
        return
    for pdir in sorted(p for p in DEPLOYS.iterdir() if p.is_dir()):
        manifest_file = pdir / "manifest.yml"
        if not manifest_file.exists():
            continue
        manifest = load(manifest_file)
        hosts = ",".join(i.host for i in manifest.spec.ingress)
        ps = (
            subprocess.run(  # noqa: S603  # fixed argv, no shell
                ["docker", "compose", "-p", pdir.name, "ps", "--format", "{{.State}}"],  # noqa: S607  # docker on PATH
                capture_output=True,
                text=True,
                check=False,
            )
            .stdout.strip()
            .replace("\n", ",")
            or "-"
        )
        print(f"{pdir.name:24} {ps:32} {hosts}")


def _applied_revision(name: str) -> str:
    """Return the short git revision of an app's checkout, or `-` if unknown.

    Workflow-managed deploys mirror their tree with rsync (no `.git`), so they
    have no local revision to report; `-` is returned rather than shelling out.
    """
    repo = project_dir(name) / "repo"
    if not (repo / ".git").exists():
        return "-"
    proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
        ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],  # noqa: S607  # git on PATH
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "-" if proc.returncode == 0 else "-"


def cmd_status(name: str) -> None:
    """Show one deployment's health, ingress, databases, and source provenance.

    Surfaces, for a single app: container/service state (`docker compose ps`),
    each ingress host with its upstream router health, the provisioned
    postgres/redis with **password-redacted** connection URLs (read back from the
    600 creds file via `read_db_env`, never the raw secret), and the source
    repo/branch plus the last applied git revision.
    """
    manifest_file = project_dir(name) / "manifest.yml"
    if not manifest_file.exists():
        sys.exit(f"nuk: {name}: no such deployment ({manifest_file} not found)")
    manifest = load(manifest_file)
    source = manifest.spec.source

    ps = (
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["docker", "compose", "-p", name, "ps", "--format", "{{.Service}}: {{.State}}"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        .stdout.strip()
        .splitlines()
    )
    print(f"deployment: {name}")
    print("containers:")
    for line in ps or ["(none running)"]:
        print(f"  {line}")

    print("ingress:")
    for ing in manifest.spec.ingress or []:
        exists, healthy = _container_state(f"{name}-{ing.service}-1")
        health = "healthy" if healthy else "unhealthy" if exists else "down"
        print(f"  https://{ing.host} -> {ing.service}:{ing.port} [{health}]")
    if not manifest.spec.ingress:
        print("  (none)")

    print("databases:")
    env = read_db_env(name)
    db_urls = [
        (kind, _redact_db_url(env.get(key)))
        for kind, key in (("postgres", "DATABASE_URL"), ("redis", "REDIS_URL"))
    ]
    shown = [(kind, url) for kind, url in db_urls if url]
    for kind, url in shown:
        print(f"  {kind}: {url}")
    if not shown:
        print("  (none provisioned)")

    print("source:")
    print(f"  repo: {source.repo or '-'}")
    print(f"  branch: {source.branch}")
    print(f"  revision: {_applied_revision(name)}")


def cmd_logs(name: str) -> None:
    """Follow compose logs for a deployment."""
    manifest = load(project_dir(name) / "manifest.yml")
    sh(*compose_args(name, manifest.raw), "logs", "-f")


def cmd_rollout(name: str) -> None:
    """Git pull + compose pull + up -d for a deployment."""
    manifest = load(project_dir(name) / "manifest.yml")
    repo = project_dir(name) / "repo"
    if (repo / ".git").exists():
        sh("git", "-C", str(repo), "pull", "--ff-only")
    # else: workflow-managed deployment — re-trigger the workflow to update the tree.
    sh(*compose_args(name, manifest.raw), "pull")
    sh(*compose_args(name, manifest.raw), "up", "-d")


def cmd_delete(name: str, purge: bool) -> None:
    """Tear down a deployment, keeping its database unless `purge` is set."""
    pdir = project_dir(name)
    if (pdir / "manifest.yml").exists():
        manifest = load(pdir / "manifest.yml")
        subprocess.run([*compose_args(name, manifest.raw), "down", "-v"], check=False)  # noqa: S603  # argv built from fixed verbs
    (DYNAMIC / f"{name}.yml").unlink(missing_ok=True)
    shutil.rmtree(pdir, ignore_errors=True)
    # The app's database is kept by default — its creds file (in SECRETS, not
    # pdir) survives rmtree and keeps nuk aware of it (see `nuk db ls`). --purge
    # is the only path that destroys data.
    if purge:
        purge_databases(name)
    elif (SECRETS / f"{name}-db.env").exists():
        print(f"{name}: database retained. `nuk db ls` to view, `nuk db purge {name}` to drop it.")


def cmd_db_ls() -> None:
    """List managed databases; flag retained ones with no live deployment."""
    if not SECRETS.exists():
        return
    for f in sorted(SECRETS.glob("*-db.env")):
        app = f.name[: -len("-db.env")]
        env = read_db_env(app)
        kinds = (
            ",".join(
                k
                for k, present in (
                    ("postgres", "DATABASE_URL" in env),
                    ("redis", "REDIS_URL" in env),
                )
                if present
            )
            or "-"
        )
        live = (DEPLOYS / app / "manifest.yml").exists()
        status = "deployed" if live else "RETAINED (no deployment — nuk db purge to drop)"
        print(f"{app:24} {kinds:16} {status}")


def cmd_db_purge(name: str) -> None:
    """Drop a retained app's database + creds."""
    purge_databases(name)
    print(f"{name}: database purged.")


# --- shell completion ---------------------------------------------------------


def _known_deployments() -> list[str]:
    """List deployment names — the same source `cmd_get` enumerates.

    Returns empty (never raises) off the controller, where DEPLOYS is absent, so
    shell completion degrades gracefully.
    """
    if not DEPLOYS.exists():
        return []
    return sorted(
        p.name for p in DEPLOYS.iterdir() if p.is_dir() and (p / "manifest.yml").exists()
    )


def complete_deployment_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for deployment-name arguments (logs/rollout/...)."""
    return [n for n in _known_deployments() if n.startswith(incomplete)]


def complete_db_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for `db purge` — retained DB creds in SECRETS.

    Purge targets a database by its creds file, which outlives the deployment
    (see `cmd_db_ls`), so this enumerates SECRETS rather than live deployments.
    """
    if not SECRETS.exists():
        return []
    names = sorted(f.name[: -len("-db.env")] for f in SECRETS.glob("*-db.env"))
    return [n for n in names if n.startswith(incomplete)]


# --- typer CLI ----------------------------------------------------------------

_EPILOG = """\
Manifest (apiVersion: nuk/v1, kind: Deployment):
  metadata.name, spec.source.{repo,branch}, spec.compose.file,
  spec.ingress[].{host,service,port}, spec.envFrom[].secretRef
  spec.ingress[] also takes optional: path (PathPrefix), stripPrefix,
    priority, www (301 www.<host> -> <host>; apex domains only),
    auth ("oauth" -> GitHub oauth2-proxy gate, "basic" -> HTTP Basic Auth)
  spec.envFrom[].secretRef -> existing env files injected into each
    ingress service's container env via the compose override (and also
    passed to `docker compose --env-file` for ${VAR} interpolation).
  spec.databases: {postgres: true, redis: true} -> per-app DB on the
    shared data stack; injects DATABASE_URL / REDIS_URL into the
    ingress service(s). Override the injection target with
    databases.attachTo: [web, worker] (explicit services, e.g. a worker
    with no ingress) or databases.attachAll: true (every compose service).
"""

app = typer.Typer(
    name="nuk",
    help="Minimal Kubernetes-shaped Docker Compose deployer.",
    epilog=_EPILOG,
    add_completion=True,
    no_args_is_help=True,
)


def _version(value: bool) -> None:
    """Eager `--version` callback: print `nuk <version>` and exit 0.

    Fires before the host-check in the app callback, so `nuk --version` works on
    any machine (the controller CD smoke check relies on this).

    Args:
        value: Whether `--version` was passed.

    Raises:
        typer.Exit: Always, when `value` is set, after printing.
    """
    if value:
        print(f"nuk {__version__}")
        raise typer.Exit


@app.callback()
def _root(
    ctx: typer.Context,
    version: Annotated[  # noqa: ARG001  # consumed by the eager callback before the body runs
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="print version and exit"),
    ] = False,
) -> None:
    """Guard every subcommand on the controller host.

    Runs after the eager `--version` callback, so `--version`/`--help` never trip
    the host check, but every actual subcommand does.

    Args:
        ctx: The typer context, used to echo the invoked subcommand in the error.
        version: Whether `--version` was passed (handled by the eager callback).

    Raises:
        SystemExit: When `/opt/nuklaut` is absent (nuk runs on the controller).
            The `org` and `update` subcommands are exempt — they run off the
            controller too (operator workstation, CI, the deploy plugin).
    """
    if ctx.invoked_subcommand in {"org", "update"}:
        return
    if not ROOT.exists():
        sys.exit(
            f"nuk: {ROOT} does not exist — nuk runs on the controller, "
            f"not your workstation. Use: ./deploy.sh nuk {ctx.invoked_subcommand}"
        )


@app.command("list")
@app.command("get")
@app.command("ls")
def _list() -> None:
    """List deployments, container state, and ingress hosts (aliases: get, ls)."""
    cmd_get()


@app.command("apply")
def _apply(
    manifest: Annotated[Path, typer.Argument(help="path to the nuk/v1 manifest")],
    repo_path: Annotated[
        str | None,
        typer.Option(
            "--repo-path",
            help="local path to use instead of cloning spec.source.repo "
            "(for workflow-driven deploys where the runner already has a checkout)",
        ),
    ] = None,
) -> None:
    """Create or update a deployment from a manifest."""
    cmd_apply(manifest, repo_path)


@app.command("status")
def _status(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_deployment_name)
    ],
) -> None:
    """Show one app's health, ingress, databases (redacted URLs), and source."""
    cmd_status(name)


@app.command("logs")
def _logs(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_deployment_name)
    ],
) -> None:
    """Follow compose logs for a deployment."""
    cmd_logs(name)


@app.command("rollout")
def _rollout(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_deployment_name)
    ],
) -> None:
    """Git pull + compose pull + up -d."""
    cmd_rollout(name)


@app.command("delete")
def _delete(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_deployment_name)
    ],
    purge: Annotated[
        bool,
        typer.Option(
            "--purge", help="also drop the app's postgres db/role + redis user (DESTROYS DATA)"
        ),
    ] = False,
) -> None:
    """Tear down a deployment (keeps its database)."""
    cmd_delete(name, purge)


db_app = typer.Typer(
    name="db", help="inspect/manage app databases (shared postgres/redis)", no_args_is_help=True
)
app.add_typer(db_app)


@db_app.command("ls")
def _db_ls() -> None:
    """List managed databases; flags retained ones with no deployment."""
    cmd_db_ls()


@db_app.command("purge")
def _db_purge(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_db_name)
    ],
) -> None:
    """Drop a retained app's database + creds."""
    cmd_db_purge(name)


def norm_ver(tag: str) -> tuple[int, ...]:
    """Numeric version tuple from a tag, for comparison.

    'v0.10.0' -> (0, 10, 0); stops at the first non-numeric part.

    Args:
        tag: A version tag, with or without a leading `v`.

    Returns:
        The leading numeric components as a tuple.
    """
    out: list[int] = []
    for part in tag.lstrip("v").split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


def latest_release_tag(repo: str = NUK_REPO) -> str | None:
    """Latest release tag for `repo` (e.g. `v0.10.0`), or None if unavailable.

    Prefers `gh` (authenticated — nuk's repo is private, so the anonymous API
    404s), falling back to the public GitHub API when gh is absent.

    Args:
        repo: The `owner/name` GitHub repo.

    Returns:
        The latest release's tag, or None on any error.
    """
    try:
        out = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["gh", "release", "view", "--repo", repo, "--json", "tagName", "-q", ".tagName"],  # noqa: S607  # gh on PATH
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        out = ""
    if out:
        return out
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310  # fixed https github api URL
            data = json.load(resp)
    except (OSError, ValueError):
        return None
    tag = data.get("tag_name") if isinstance(data, dict) else None
    return tag if isinstance(tag, str) else None


def cmd_update(to: str | None, check: bool) -> None:
    """Install the latest nuk release (or an explicit ref) via `uv tool install`.

    Args:
        to: Explicit ref/tag to install (bypasses the up-to-date check, so it also
            supports pinning/downgrade); None installs the latest release.
        check: Only report installed-vs-latest; install nothing.

    Raises:
        SystemExit: If the latest release cannot be resolved, or the uv install fails.
    """
    current = __version__
    target = to or latest_release_tag()
    if not target:
        sys.exit("nuk update: could not resolve the latest release (network?). Pass --to <ref>.")
    if check:
        print(f"nuk {current} installed - latest is {target}")
        return
    if to is None and norm_ver(target) and norm_ver(target) <= norm_ver(current):
        print(f"nuk {current} is already up to date ({target})")
        return
    print(f"updating nuk {current} -> {target} via uv tool install...")
    try:
        sh("uv", "tool", "install", "--force", "--from", f"{NUK_GIT}@{target}", "nuk")
    except (subprocess.SubprocessError, OSError) as e:
        sys.exit(
            f"nuk update: uv install failed ({e}). Is uv installed? "
            f"Manual: uv tool install --from {NUK_GIT}@{target} nuk"
        )
    print(f"nuk updated to {target} - run `nuk --version` to confirm")


def _emit(value: object) -> str:
    """Render an org value for the shell: bools lowercased, blocks as YAML, else str."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return yaml.safe_dump(value, sort_keys=False).rstrip()
    return str(value)


org_app = typer.Typer(
    name="org",
    help="resolve + read the org capability manifest (nukorg/v1) — runs off-controller",
    no_args_is_help=True,
)
app.add_typer(org_app)


@org_app.command("resolve")
def _org_resolve(
    repo_path: Annotated[
        str, typer.Option("--repo-path", help="git checkout to read origin from")
    ] = ".",
) -> None:
    """Print the GitHub org of a repo's origin (its `<org>/infra` holds the manifest)."""
    org = origin_org(repo_path)
    if not org:
        sys.exit("nuk org resolve: no github origin remote found")
    print(org)


@org_app.command("validate")
def _org_validate(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
) -> None:
    """Validate a nukorg/v1 Org manifest; exit nonzero if invalid."""
    org = load_org(path)
    print(f"OK: {path} is a valid nukorg/v1 Org ({org.metadata.name})")


@org_app.command("get")
def _org_get(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
    key: Annotated[str, typer.Argument(help="dotted key, e.g. facilities.auth")],
) -> None:
    """Print one value from an Org manifest by dotted key (for bootstrap + plugin)."""
    print(_emit(org_get(load_org(path), key)))


@org_app.command("show")
def _org_show(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
) -> None:
    """Print the validated Org manifest as normalized YAML."""
    print(yaml.safe_dump(load_org(path).model_dump(by_alias=True), sort_keys=False), end="")


@app.command("update")
def _update(
    to: Annotated[
        str | None, typer.Option("--to", help="ref/tag to install (default: latest release)")
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="report installed vs latest; install nothing")
    ] = False,
) -> None:
    """Update the installed nuk to the latest release (or --to <ref>) via uv."""
    cmd_update(to, check)


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
