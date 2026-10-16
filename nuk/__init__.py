#!/usr/bin/env python3
"""nuk — minimal Kubernetes-shaped Docker Compose deployer.

Manifests (apiVersion: nuk/v1, kind: Deployment | Facility) describe one compose
project each: its source, ingress, env files, databases, and placement. Deploy
state lives in /opt/nuklaut/, the convergence loop's state and release history in
/var/lib/nuk/, host identity and trust anchors in /etc/nuklaut/. No daemon.
"""

from __future__ import annotations

import fcntl
import grp
import io
import json
import os
import re
import shlex
import shutil
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
import sys
import tarfile
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, Self, cast

import typer
import yaml
from pydantic import (
    ValidationError,
)

from nuk import compose as compose
from nuk import databases as databases
from nuk import facility as facility
from nuk import ingress as ingress
from nuk import models as models
from nuk import org as org
from nuk import paths
from nuk import provenance as provenance
from nuk import sources as sources
from nuk import status as status
from nuk.compose import (
    _compose_images,
    _resolve_image_digest,
    compose_args,
    resolve_db_services,
    resolve_env_from,
    write_override,
)
from nuk.compose import (
    _parse_compose_images_json as _parse_compose_images_json,
)
from nuk.compose import (
    _primary_container as _primary_container,
)
from nuk.compose import (
    _published_port as _published_port,
)
from nuk.compose import (
    compose_service_names as compose_service_names,
)
from nuk.databases import (
    _container_state,
    _redact_db_url,
    data_host_ip,
    provision_databases,
    purge_databases,
    read_db_env,
)
from nuk.databases import (
    _db_password as _db_password,
)
from nuk.databases import (
    _lit as _lit,
)
from nuk.databases import (
    _pg_driver as _pg_driver,
)
from nuk.databases import (
    _pg_url as _pg_url,
)
from nuk.databases import (
    _psql as _psql,
)
from nuk.databases import (
    _pw_from_url as _pw_from_url,
)
from nuk.databases import (
    _redis_admin as _redis_admin,
)
from nuk.databases import (
    _redis_url as _redis_url,
)
from nuk.databases import (
    _require_container as _require_container,
)
from nuk.databases import (
    derive_db_password as derive_db_password,
)
from nuk.databases import (
    ensure_postgres as ensure_postgres,
)
from nuk.databases import (
    ensure_redis as ensure_redis,
)
from nuk.databases import (
    load_db_seed as load_db_seed,
)
from nuk.databases import (
    preflight_data_stack as preflight_data_stack,
)
from nuk.databases import (
    write_db_env as write_db_env,
)
from nuk.facility import (
    APPLY_ALL as APPLY_ALL,
)
from nuk.facility import (
    DEPLOYMENT_DIR,
    FACILITY_DIR,
    TreeContext,
    _router_present,
    env_facility,
    facility_health,
    load_deployments,
    load_facilities,
    route_vocabulary,
)
from nuk.facility import (
    ROUTER_PORT as ROUTER_PORT,
)
from nuk.facility import (
    _tree_root as _tree_root,
)
from nuk.ingress import (
    RouteResult,
    _authorized_ingress,
    _rule,
    backend_address,
    reap_legacy_worker_routers,
    write_ingress,
)
from nuk.ingress import (
    _refuse_route as _refuse_route,
)
from nuk.ingress import (
    build_override as build_override,
)
from nuk.ingress import (
    render_edge_routers as render_edge_routers,
)
from nuk.models import (
    _MANIFEST_ADAPTER as _MANIFEST_ADAPTER,
)
from nuk.models import (
    AnyManifest as AnyManifest,
)
from nuk.models import (
    Compose as Compose,
)
from nuk.models import (
    Databases as Databases,
)
from nuk.models import (
    Deployment,
    Facility,
    Ingress,
    Migrate,
    Spec,
    Strategy,
    load,
)
from nuk.models import (
    EnvFrom as EnvFrom,
)
from nuk.models import (
    EnvProvide as EnvProvide,
)
from nuk.models import (
    FacilitySpec as FacilitySpec,
)
from nuk.models import (
    Health as Health,
)
from nuk.models import (
    Metadata as Metadata,
)
from nuk.models import (
    Placement as Placement,
)
from nuk.models import (
    Postgres as Postgres,
)
from nuk.models import (
    Provides as Provides,
)
from nuk.models import (
    Role as Role,
)
from nuk.models import (
    RouteProvide as RouteProvide,
)
from nuk.models import (
    Source as Source,
)
from nuk.models import (
    StrategyHealth as StrategyHealth,
)
from nuk.models import (
    _NullTolerant as _NullTolerant,
)
from nuk.org import (
    _ENTRY_ROLES,
    Delegation,
    Host,
    Org,
    TenantRegistry,
    check_cross_zone_patterns,
    load_cached_delegations,
    load_delegations,
    load_org,
    resolve_host_owner,
    resolve_manifest,
    store_delegations,
    validate_delegations,
)
from nuk.org import (
    DELEGATIONS_CACHE_FILE as DELEGATIONS_CACHE_FILE,
)
from nuk.org import (
    DELEGATIONS_FILE as DELEGATIONS_FILE,
)
from nuk.org import (
    TENANTS_FILE as TENANTS_FILE,
)
from nuk.org import (
    Delegations as Delegations,
)
from nuk.org import (
    Facilities as Facilities,
)
from nuk.org import (
    host_in_domains as host_in_domains,
)
from nuk.org import (
    load_tenants as load_tenants,
)
from nuk.org import (
    specificity as specificity,
)
from nuk.paths import (
    CONVERGE_STATE as CONVERGE_STATE,
)
from nuk.paths import (
    CONVERGE_STATUS as CONVERGE_STATUS,
)
from nuk.paths import (
    DB_SEED_ENV as DB_SEED_ENV,
)
from nuk.paths import (
    DEPLOYS as DEPLOYS,
)
from nuk.paths import (
    DYNAMIC as DYNAMIC,
)
from nuk.paths import (
    HOST_ENV as HOST_ENV,
)
from nuk.paths import (
    KNOWN_HOSTS as KNOWN_HOSTS,
)
from nuk.paths import (
    RELEASES as RELEASES,
)
from nuk.paths import (
    ROOT as ROOT,
)
from nuk.paths import (
    SECRETS as SECRETS,
)
from nuk.paths import (
    SIGNERS_DIR as SIGNERS_DIR,
)
from nuk.paths import (
    SOURCES_FILE as SOURCES_FILE,
)
from nuk.provenance import (
    RELEASE_LIMIT as RELEASE_LIMIT,
)
from nuk.provenance import (
    latest_release_tag,
    read_provenance_history,
    write_provenance,
)
from nuk.provenance import (
    read_provenance as read_provenance,
)
from nuk.records import (
    ConvergeStatus,
    Json,
    LoggingStatus,
    ManifestKind,
    ManifestResult,
    SourceBlock,
)
from nuk.records import (
    ManifestOutcome as ManifestOutcome,
)
from nuk.sources import (
    SOURCE_BRANCH as SOURCE_BRANCH,
)
from nuk.sources import (
    SourceEntry,
    load_sources,
    record_applied,
    source_state_dir,
    sync_source,
)
from nuk.sources import (
    SourcesFile as SourcesFile,
)
from nuk.sources import (
    assert_not_downgrade as assert_not_downgrade,
)
from nuk.sources import (
    git_ssh_command as git_ssh_command,
)
from nuk.sources import (
    resolve_signed_tag as resolve_signed_tag,
)
from nuk.sources import (
    verify_tag as verify_tag,
)
from nuk.status import (
    _VERSION_RE as _VERSION_RE,
)
from nuk.status import (
    _annotate_routers as _annotate_routers,
)
from nuk.status import (
    _drift_for as _drift_for,
)
from nuk.status import (
    _dynamic_routers as _dynamic_routers,
)
from nuk.status import (
    _git_provenance as _git_provenance,
)
from nuk.status import (
    _list_workflows as _list_workflows,
)
from nuk.status import (
    _overview_features as _overview_features,
)
from nuk.status import (
    _overview_ingress_fields as _overview_ingress_fields,
)
from nuk.status import (
    _overview_provenance as _overview_provenance,
)
from nuk.status import (
    _probe as _probe,
)
from nuk.status import (
    _read_app_overview as _read_app_overview,
)
from nuk.status import (
    _read_version as _read_version,
)
from nuk.status import (
    _soll_vs_ist,
    build_overview,
)
from nuk.util import (
    NukError,
    _atomic_write,
    _full_commit_sha,
    _git_try,
    _int_or_none,
    _iso_utc_now,
    _read_env_file,
    _read_json_safe,
    _read_yaml_safe,
    _str_or_none,
    die,
    git_origin,
    norm_ver,
    origin_org,
    sh,
)
from nuk.util import (
    _chown_deploy as _chown_deploy,
)
from nuk.util import (
    _git as _git,
)
from nuk.util import (
    _is_ancestor as _is_ancestor,
)
from nuk.util import (
    _safe_ident as _safe_ident,
)
from nuk.util import (
    _str_list as _str_list,
)
from nuk.util import (
    github_url as github_url,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

__version__ = "2.6.1"  # bumped on release by .github/workflows/release.yml

# Named, never globbed: the infra tree also carries nuklaut.org.yml,
# nuklaut.test.org.yml and nuklaut.min.org.yml, and a glob picking one of those
# would have the edge resolve every backend IP from a template or a test fixture.
DEFAULT_ORG_FILE = "nuklaut.astrocloud.org.yml"

# Shared data stack — owned, reproducible source vendored at
# files/docker-compose.data.yml (bring it up once on the controller). Apps reach
# these by their container names over the private `data` network. provision_*
# preflights both containers (see preflight_data_stack) before any docker exec.
PG_CONTAINER = "nuk-postgres"
REDIS_CONTAINER = "nuk-redis"

# The capability name a Deployment's `spec.databases` block asks for; the
# data-stack facility declares it via spec.provides.env.capability.
_DATABASES_CAPABILITY = "databases"

# nuk distributes as a normal Python package: run ephemerally with
#   uvx --from git+https://github.com/astrojones/nuk@<ref> nuk ...
# or install/upgrade a pinned copy with `nuk update` (→ uv tool install --from …).
NUK_REPO = "astrojones/nuk"
NUK_GIT = f"git+https://github.com/{NUK_REPO}"


# --- wire records -------------------------------------------------------------
# Everything nuk writes to disk or prints is a closed schema. These records own the exact
# key set, key order and present-vs-absent rules, so no call site re-spells them. yaml.safe_dump
# sorts keys, so for the two YAML outputs only the key set and presence matter; the JSON ones
# (converge status, provenance, overview) keep insertion order, which is the documented order.
# `from_wire` is tolerant wherever the source can be stale or half-written (overview,
# provenance): a value of the wrong type degrades to None/default instead of raising.


# Compose override (write-only)


@dataclass(frozen=True)
class ServiceWiring:
    """One service's entry in `compose.override.yml`."""

    networks: list[str]
    ports: list[str] = field(default_factory=list)
    env_file: list[str] = field(default_factory=list)

    def to_wire(self) -> dict[str, Json]:
        """`networks` is always present (even empty); `ports`/`env_file` only when non-empty."""
        out: dict[str, Json] = {"networks": [*self.networks]}
        if self.ports:
            out["ports"] = [*self.ports]
        if self.env_file:
            out["env_file"] = [*self.env_file]
        return out


@dataclass(frozen=True)
class ComposeOverride:
    """The whole `compose.override.yml` document."""

    services: dict[str, ServiceWiring]
    external_networks: list[str]

    def to_wire(self) -> dict[str, Json]:
        """`networks` is always present, even as `{}`."""
        return {
            "services": {k: v.to_wire() for k, v in self.services.items()},
            "networks": {n: {"external": True} for n in self.external_networks},
        }


# Traefik dynamic config (write-only)


@dataclass(frozen=True)
class TraefikRouter:
    """One file-provider router."""

    rule: str
    entry_points: list[str]
    service: str
    tls_cert_resolver: str | None = None
    middlewares: list[str] = field(default_factory=list)
    priority: int | None = None

    def to_wire(self) -> dict[str, Json]:
        """`tls`, `middlewares` and `priority` are omitted unless set / non-empty."""
        out: dict[str, Json] = {
            "rule": self.rule,
            "entryPoints": [*self.entry_points],
            "service": self.service,
        }
        if self.tls_cert_resolver is not None:
            out["tls"] = {"certResolver": self.tls_cert_resolver}
        if self.middlewares:
            out["middlewares"] = [*self.middlewares]
        if self.priority is not None:
            out["priority"] = self.priority
        return out


@dataclass(frozen=True)
class TraefikService:
    """A single-backend load balancer."""

    url: str

    def to_wire(self) -> dict[str, Json]:
        """The `loadBalancer.servers[]` shape Traefik expects."""
        return {"loadBalancer": {"servers": [{"url": self.url}]}}


@dataclass(frozen=True)
class StripPrefix:
    """The `stripPrefix` middleware."""

    prefixes: list[str]

    def to_wire(self) -> dict[str, Json]:
        """Wrap the prefixes under the middleware's type key."""
        return {"stripPrefix": {"prefixes": [*self.prefixes]}}


@dataclass(frozen=True)
class RedirectRegex:
    """The `redirectRegex` middleware (the www -> apex 301)."""

    regex: str
    replacement: str
    permanent: bool

    def to_wire(self) -> dict[str, Json]:
        """Wrap the three fields under the middleware's type key."""
        return {
            "redirectRegex": {
                "regex": self.regex,
                "replacement": self.replacement,
                "permanent": self.permanent,
            }
        }


type TraefikMiddleware = StripPrefix | RedirectRegex


@dataclass(frozen=True)
class TraefikConfig:
    """The whole Traefik dynamic file (`http:` only)."""

    routers: dict[str, TraefikRouter]
    services: dict[str, TraefikService]
    middlewares: dict[str, TraefikMiddleware] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Json]:
        """`middlewares` is omitted when there are none."""
        http: dict[str, Json] = {
            "routers": {k: v.to_wire() for k, v in self.routers.items()},
            "services": {k: v.to_wire() for k, v in self.services.items()},
        }
        if self.middlewares:
            http["middlewares"] = {k: v.to_wire() for k, v in self.middlewares.items()}
        return {"http": http}


# Provenance / docker


@dataclass(frozen=True)
class ReleaseEntry:
    """One line of `releases/<name>.jsonl`."""

    repo: str | None = None
    branch: str | None = None
    commit: str | None = None
    image_digest: str | None = None
    applied_at: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """All five keys, always, in this order."""
        return {
            "repo": self.repo,
            "branch": self.branch,
            "commit": self.commit,
            "imageDigest": self.image_digest,
            "appliedAt": self.applied_at,
        }

    @classmethod
    def from_wire(cls, data: Mapping[str, object]) -> Self:
        """Non-string values read as None; legacy entries with fewer keys read fine."""
        return cls(
            _str_or_none(data.get("repo")),
            _str_or_none(data.get("branch")),
            _str_or_none(data.get("commit")),
            _str_or_none(data.get("imageDigest")),
            _str_or_none(data.get("appliedAt")),
        )

    def same_release(self, other: Self) -> bool:
        """Same repo/branch/commit/digest: a re-apply refreshes the entry, not the history."""
        return (self.repo, self.branch, self.commit, self.image_digest) == (
            other.repo,
            other.branch,
            other.commit,
            other.image_digest,
        )


@dataclass(frozen=True)
class ComposeImage:
    """One row of `docker compose images --format json` (docker's PascalCase keys)."""

    repository: str | None
    tag: str | None
    container_name: str | None = None
    image_id: str | None = None

    @classmethod
    def from_wire(cls, row: Mapping[str, object]) -> Self:
        """Non-string values read as None."""
        return cls(
            _str_or_none(row.get("Repository")),
            _str_or_none(row.get("Tag")),
            _str_or_none(row.get("ContainerName")),
            _str_or_none(row.get("ID")),
        )


@dataclass(frozen=True)
class GitProvenance:
    """HEAD's full sha, committer date and web URL; the empty instance means no checkout."""

    full_commit: str | None = None
    last_commit: str | None = None
    repo_url: str | None = None


# Overview (printed by `nuk status`). The AppSource/AppIngress/AppFeatures readers are NOT the
# pydantic models: the overview reads a possibly stale, unvalidated manifest.yml and must
# degrade, not raise (e.g. `Source.branch` defaults to "main", the overview prints null).


@dataclass(frozen=True)
class AppSource:
    """`spec.source` as the overview shows it."""

    repo: str | None = None
    branch: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """Both keys, always."""
        return {"repo": self.repo, "branch": self.branch}

    @classmethod
    def from_wire(cls, obj: object) -> Self:
        """Non-string values read as None."""
        data = obj if isinstance(obj, dict) else {}
        return cls(_str_or_none(data.get("repo")), _str_or_none(data.get("branch")))


@dataclass(frozen=True)
class AppIngress:
    """One `spec.ingress[]` entry as the overview shows it."""

    host: str
    service: str | None = None
    port: int | None = None
    path: str | None = None
    auth: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """All five keys, always."""
        return {
            "host": self.host,
            "service": self.service,
            "port": self.port,
            "path": self.path,
            "auth": self.auth,
        }

    @classmethod
    def from_wire(cls, obj: object) -> Self | None:
        """None for an entry without a usable host (the overview skips those)."""
        if not isinstance(obj, dict):
            return None
        host = obj.get("host")
        if not isinstance(host, str) or not host:
            return None
        return cls(
            host,
            _str_or_none(obj.get("service")),
            _int_or_none(obj.get("port")),
            _str_or_none(obj.get("path")),
            _str_or_none(obj.get("auth")),
        )


@dataclass(frozen=True)
class AppFeatures:
    """The declared backing services."""

    postgres: bool = False
    redis: bool = False
    postgres_driver: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """All three keys, always."""
        return {
            "postgres": self.postgres,
            "redis": self.redis,
            "postgresDriver": self.postgres_driver,
        }

    @classmethod
    def from_databases(cls, obj: object) -> Self:
        """Read a raw `spec.databases` value; same truthiness the manifest has always had."""
        data = obj if isinstance(obj, dict) else {}
        pg = data.get("postgres")
        driver = pg.get("driver") if isinstance(pg, dict) else None
        return cls(bool(pg), bool(data.get("redis")), _str_or_none(driver))


@dataclass(frozen=True)
class Workflow:
    """A GitHub Actions workflow file."""

    file: str
    name: str
    triggers: list[str] = field(default_factory=list)

    def to_wire(self) -> dict[str, Json]:
        """All three keys, always."""
        return {"file": self.file, "name": self.name, "triggers": [*self.triggers]}


@dataclass(frozen=True)
class RouterStatus:
    """A router nuk rendered, with the optional live probe."""

    id: str
    rule: str
    live: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """All three keys, always; `live` is null unless probed."""
        return {"id": self.id, "rule": self.rule, "live": self.live}


@dataclass(frozen=True)
class AppOverview:
    """One app's entry in the overview."""

    name: str
    hosts: list[str]
    source: AppSource | None
    repo_url: str | None
    commit: str | None
    commit_url: str | None
    last_commit: str | None
    version: str | None
    routers: list[RouterStatus]
    drift: Literal["in-sync", "drift", "unknown"]
    features: AppFeatures
    workflows: list[Workflow]
    ingress: list[AppIngress]
    notes: list[str]
    image_digest: str | None

    def to_wire(self) -> dict[str, Json]:
        """Every key, always (null, never omitted), in the order `nukview` has been reading."""
        return {
            "name": self.name,
            "hosts": [*self.hosts],
            "source": self.source.to_wire() if self.source is not None else None,
            "repoUrl": self.repo_url,
            "commit": self.commit,
            "commitUrl": self.commit_url,
            "lastCommit": self.last_commit,
            "version": self.version,
            "routers": [r.to_wire() for r in self.routers],
            "drift": self.drift,
            "features": self.features.to_wire(),
            "workflows": [w.to_wire() for w in self.workflows],
            "ingress": [i.to_wire() for i in self.ingress],
            "notes": [*self.notes],
            "imageDigest": self.image_digest,
        }


@dataclass(frozen=True)
class SollVsIst:
    """`status --all`: declared org hosts against what this command observed."""

    declared_hosts: int
    observed_hosts: int
    declared_apps: int | None
    observed_apps: int

    def to_wire(self) -> dict[str, Json]:
        """All four keys, always; `declaredApps` is null (nukorg/v1 declares no apps)."""
        return {
            "declaredHosts": self.declared_hosts,
            "observedHosts": self.observed_hosts,
            "declaredApps": self.declared_apps,
            "observedApps": self.observed_apps,
        }


@dataclass(frozen=True)
class Overview:
    """The org-wide document `nuk status` prints."""

    apps: list[AppOverview]
    live_routing_available: bool
    nuk_root: str
    generated_at: str
    errors: list[str]
    converge: ConvergeStatus | None = None
    hosts: list[Host] | None = None
    soll_vs_ist: SollVsIst | None = None

    def to_wire(self) -> dict[str, Json]:
        """`converge`, `hosts` and `sollVsIst` are absent unless set (the last two: `--all`)."""
        out: dict[str, Json] = {
            "apps": [a.to_wire() for a in self.apps],
            "liveRoutingAvailable": self.live_routing_available,
            "nukRoot": self.nuk_root,
            "generatedAt": self.generated_at,
            "errors": [*self.errors],
        }
        if self.converge is not None:
            out["converge"] = self.converge.to_wire()
        if self.hosts is not None:
            out["hosts"] = [h.model_dump(by_alias=True) for h in self.hosts]
        if self.soll_vs_ist is not None:
            out["sollVsIst"] = self.soll_vs_ist.to_wire()
        return out


@dataclass(frozen=True)
class HostAuth:
    """Who may render which host: the delegation-aware resolution (spec §3).

    Built once per cycle from the platform registry plus every owner's loans, so a
    delegation committed by another source is already honoured in the same run (spec
    §3.5). A tenant source renders a host only when `resolve` names it; the platform
    source is ungated and never consults this. Both fields are inputs to
    `resolve_host_owner` — the resolution itself lives there, not here.
    """

    registry: TenantRegistry
    delegations: dict[str, list[Delegation]]

    def resolve(self, host: str) -> str | None:
        """The tenant allowed to render `host`, or None (nobody / the platform)."""
        return resolve_host_owner(host, self.registry, self.delegations)


def org_get(org: Org, dotted: str) -> object:
    """Return a value from an Org by dotted alias path (e.g. `facilities.auth`).

    Args:
        org: The validated Org.
        dotted: Dot-separated key path using the manifest's YAML (alias) names.

    Returns:
        The value at that path (scalar, list, or dict).

    Raises:
        NukError: If any path segment is missing.
    """
    node: object = org.model_dump(by_alias=True)
    for part in dotted.split("."):
        if not isinstance(node, dict):
            die(f"nuk org get: no such key: {dotted}")
        current = cast("dict[str, object]", node)
        if part not in current:
            die(f"nuk org get: no such key: {dotted}")
        node = current[part]
    return node


def project_dir(name: str) -> Path:
    """Return the on-disk deployment directory for an app."""
    return paths.DEPLOYS / name


def _active_colour_file(name: str) -> Path:
    """The file recording an app's currently live colour."""
    return project_dir(name) / "active-colour"


def active_colour(name: str) -> str:
    """Return an app's currently live colour, defaulting to `blue`."""
    path = _active_colour_file(name)
    try:
        colour = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "blue"
    return colour or "blue"


def idle_colour(active: str) -> str:
    """Return the colour opposite `active` (`blue` ↔ `green`)."""
    return "green" if active == "blue" else "blue"


def record_active_colour(name: str, colour: str) -> None:
    """Persist `colour` as an app's currently live colour."""
    path = _active_colour_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{colour}\n", encoding="utf-8")


def _migrated_digest_file(name: str) -> Path:
    """The file recording the image digest the last migration ran against."""
    return project_dir(name) / "migrated-digest"


def migrated_digest(name: str) -> str | None:
    """Return the digest the last migration ran against, or `None` if never run."""
    try:
        return _migrated_digest_file(name).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def record_migrated_digest(name: str, digest: str) -> None:
    """Persist `digest` as the image digest the last migration ran against."""
    path = _migrated_digest_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{digest}\n", encoding="utf-8")


def _router_dialect_file(name: str) -> Path:
    """The file recording an app's deployed router dialect."""
    return project_dir(name) / "router-dialect"


def router_dialect(name: str) -> str:
    """Return an app's deployed router dialect, defaulting to `edge`.

    Persisted by `_apply_blue_green` beside `active-colour`, so a rollback — which
    has no facilities/ in its tree and so cannot detect router mode — replays the
    dialect the apply actually wrote.
    """
    path = _router_dialect_file(name)
    try:
        dialect = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "edge"
    return dialect or "edge"


def record_router_dialect(name: str, dialect: str) -> None:
    """Persist `dialect` as an app's deployed router dialect."""
    path = _router_dialect_file(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{dialect}\n", encoding="utf-8")


def await_healthy(  # noqa: PLR0913  # one keyword per probe input; all read, none derived
    container: str,
    path: str,
    *,
    timeout: int,
    interval: float,
    port: int = 8000,
    exec_: Callable[..., None] = sh,
) -> None:
    """Block until an idle colour's container answers its health path.

    Polls `docker exec <container> python -c "<urllib request>"` — Kolbe's own
    readiness pattern — every `interval` seconds until it exits zero, or raises
    once `timeout` seconds have elapsed. The blue-green rollout calls this
    before flipping the router to the new colour.

    Args:
        container: The compose container name to probe.
        path: The HTTP path that proves the colour is up.
        timeout: Seconds to keep polling before giving up.
        interval: Seconds between polls.
        port: The in-container port the service listens on (spec.strategy.health.port).
        exec_: The command runner (defaults to `sh`); injected for tests.

    Raises:
        ValueError: If the container never answered within `timeout` seconds.
    """
    probe = f"import urllib.request; urllib.request.urlopen('http://localhost:{port}{path}')"
    deadline = time.monotonic() + timeout
    while True:
        try:
            exec_("docker", "exec", container, "python", "-c", probe)
        except (subprocess.SubprocessError, OSError):
            if time.monotonic() >= deadline:
                msg = f"container {container!r} did not answer {path!r} within {timeout}s"
                raise ValueError(msg) from None
            time.sleep(interval)
        else:
            return


def _manifest_file(name: str) -> Path:
    """The persisted copy of an app's last applied manifest."""
    return project_dir(name) / "manifest.yml"


def _repo_dir(name: str) -> Path:
    """An app's cloned or mirrored source tree."""
    return project_dir(name) / "repo"


def _router_file(name: str) -> Path:
    """An app's Traefik file-provider doc."""
    return paths.DYNAMIC / f"{name}.yml"


def _db_env_path(app: str) -> Path:
    """An app's DB creds env-file — also the marker that nuk still tracks its database."""
    return paths.SECRETS / f"{app}-db.env"


def _db_env_apps() -> list[str]:
    """Apps with a DB creds file, deployed or retained."""
    if not paths.SECRETS.exists():
        return []
    return sorted(f.name.removesuffix("-db.env") for f in paths.SECRETS.glob("*-db.env"))


def persist_manifest(spec: Spec, src_path: Path, dest: Path, repo_path: str | None) -> None:
    """Write the deployment manifest to the controller for nukview to read.

    Copied verbatim, except: when applied with --repo-path and the manifest did
    not declare spec.source.repo, stamp it from the checkout's git origin. This
    gives nukview a repo link for workflow-deployed apps, whose CI passes
    --repo-path and whose manifests usually omit source.repo.

    Args:
        spec: The manifest's typed spec; only decides whether to stamp.
        src_path: Path the manifest was read from.
        dest: Destination path on the controller.
        repo_path: The --repo-path checkout, if any.
    """
    origin = git_origin(repo_path) if repo_path else None
    if not (origin and not spec.source.repo):
        shutil.copy(src_path, dest)
        return
    # Re-read the file: the typed spec drops unknown fields and key order, and the
    # stamped copy must keep what the operator wrote.
    doc: object = yaml.safe_load(src_path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        msg = f"{src_path}: manifest is not a mapping"
        raise TypeError(msg)
    body = doc.get("spec") or {}
    source = body.get("source") or {}
    body["source"] = {**source, "repo": origin}
    doc["spec"] = body
    dest.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


# The gates the pre-facility code hardcoded. Retained for the legacy all-in-one
# path — a single-host controller with no facilities dir — so its renders stay
# byte-identical (spec §12). A tree that ships facilities/ overrides it entirely;
# test_shipped_facilities_reproduce_the_default_vocabulary keeps the two in step.
# Keys are route CAPABILITY names; today `ingress[].auth: basic` names the capability `basic`.
DEFAULT_ROUTE_VOCAB: dict[str, list[str]] = {"basic": ["auth@file"]}


def _container_name(name: str, service: str, colour: str | None = None) -> str:
    """The runtime container name docker compose gives an app's service.

    ASSUMPTION: every app compose file sets NO `container_name`, so compose's
    DEFAULT naming applies — `<name>-<service>-<colour>-1` (the project name is the
    deployment name, the `-<colour>` segment is present only for blue-green, and the
    single replicas nuk deploys always land on index `-1`). An app that pinned
    `container_name` would break both callers at once. The router backend
    (write_ingress) and the health probe (`_apply_blue_green`) must name the same
    container, so both go through here.
    """
    return f"{name}-{service}{f'-{colour}' if colour else ''}-1"


def build_ingress(  # noqa: C901, PLR0912, PLR0914  # one router-build loop; clean extraction would obscure the per-field ordering
    name: str,
    ingress: list[Ingress],
    vocab: dict[str, list[str]],
    *,
    colour: str | None = None,
    dialect: str = "edge",
) -> TraefikConfig | None:
    """Render the Traefik file-provider doc, or None to remove the dynamic file.

    Each entry needs host + (service/port, a local docker "edge"-network
    container) or (address, a remote "<ip>:<port>" backend — e.g. a libvirt VM
    on another host, reached over the private vswitch/cloud-network). Optional,
    all backward-compatible:
      path        adds PathPrefix(`<path>`) to the router rule
      stripPrefix strip `path` before proxying (needs path)
      priority    explicit router priority (Traefik else ranks by rule length)
      www         also answer www.<host> with a 301 to <host> (opt-in; apex only)
      auth        "basic" -> HTTP Basic Auth (the route capability `basic`, middleware auth@file;
                  refused unless a Facility in the tree provides it)

    Args:
        name: The deployment name, used to prefix router/service ids.
        ingress: The raw `spec.ingress[]` entries.
        vocab: Route capabilities declared by the facilities in the git tree,
            mapped to their middleware chains (see route_vocabulary). A router
            that asks for a capability absent from this mapping is refused.
        colour: Optional blue-green colour. When set, each docker-named backend
            points at that colour's service container
            (`{name}-{service}-{colour}-1`) instead of the colourless
            `{name}-{service}-1`. Remote `address` backends are unaffected.
        dialect: The entrypoint/TLS flavour. `"edge"` (default) is the internet-
            facing edge: `websecure`, the letsencrypt cert resolver, and the
            branded `maintenance-errors@file` page. `"mesh"` is the app-host
            router, which reaches Traefik over the private mesh only: the `mesh`
            entrypoint, no TLS (terminated at the edge), no edge `global.yml`
            middleware. The app-host router serves the WATCHED FILE PROVIDER by URL
            (its docker provider is off), so these are file-provider routers, never
            docker-label routers. Backend URL logic is identical in both.

    Returns:
        The Traefik dynamic doc, or None when there is no ingress.
    """
    if not ingress:
        return None
    is_mesh = dialect == "mesh"
    entry_point = "mesh" if is_mesh else "websecure"
    cert_resolver = None if is_mesh else "letsencrypt"
    routers: dict[str, TraefikRouter] = {}
    services: dict[str, TraefikService] = {}
    middlewares: dict[str, TraefikMiddleware] = {}
    for i, ing in enumerate(ingress):
        rid = f"{name}-{i}"
        mw: list[str] = []
        # ⚠ The refusals below are load-bearing. The chain this replaced once had no
        #   `else`, and an unrecognised value fell through to a router with no auth
        #   middleware and no error — a security control failing OPEN. The lookup
        #   keeps that closed and widens it: an undeclared capability, and a
        #   capability whose chain is empty, are BOTH refusals (spec §5.4).
        want = ing.auth
        if want is not None:
            capability = want
            if capability not in vocab:
                msg = (
                    f"ingress.auth={want!r} maps to capability {capability!r}, which no "
                    f"facility in the tree provides (declared: {sorted(vocab) or 'none'}). "
                    f"Refusing to render an UNAUTHENTICATED router for a route that "
                    f"asked to be gated — apply a Facility declaring "
                    f"spec.provides.route.capability={capability!r} first."
                )
                raise ValueError(msg)
            if not vocab[capability]:
                msg = (
                    f"ingress.auth={want!r} resolves to an EMPTY middleware list. Refusing "
                    f"to render an ungated router."
                )
                raise ValueError(msg)
            mw += vocab[capability]
        if ing.path and ing.strip_prefix:
            sid = f"{rid}-strip"
            middlewares[sid] = StripPrefix(prefixes=[ing.path])
            mw.append(sid)
        # Every app router inherits the controller-wide branded maintenance page:
        # 502-504 from the backend → the maintenance service (see global.yml). The
        # middleware is provider-qualified (@file) since it lives in global.yml.
        # Only the edge ships that file; the mesh dialect leaves it off.
        if not is_mesh:
            mw.append("maintenance-errors@file")
        routers[rid] = TraefikRouter(
            rule=_rule(ing),
            entry_points=[entry_point],
            service=rid,
            tls_cert_resolver=cert_resolver,
            middlewares=mw,
            priority=ing.priority,
        )
        # `address` (remote host:port) bypasses the local edge-network container
        # naming convention entirely — used for backends on another host (e.g. a
        # libvirt VM reached over the private vswitch/cloud-network).
        if ing.address:
            backend = ing.address
        else:
            # The Ingress validator requires service+port unless address is set.
            assert ing.service is not None  # noqa: S101  # narrows the optional for ty
            assert ing.port is not None  # noqa: S101  # narrows the optional for ty
            backend = f"{_container_name(name, ing.service, colour)}:{ing.port}"
        services[rid] = TraefikService(url=f"http://{backend}")
        if ing.www:
            host = ing.host
            wid, rdid = f"{rid}-www", f"{rid}-www-redirect"
            middlewares[rdid] = RedirectRegex(
                regex=rf"^https?://www\.{re.escape(host)}/(.*)",
                replacement=f"https://{host}/${{1}}",
                permanent=True,
            )
            routers[wid] = TraefikRouter(
                rule=f"Host(`www.{host}`)",
                entry_points=[entry_point],
                service=rid,
                tls_cert_resolver=cert_resolver,
                middlewares=[rdid],
            )
    return TraefikConfig(routers=routers, services=services, middlewares=middlewares)


def read_self() -> tuple[str, str | None]:
    """Return (role, private_ip) for THIS host from /etc/nuklaut/host.env.

    cloud-init writes ROLE + PRIVATE_IP there (world-readable, no secrets). When
    the file is absent or unparseable — a legacy single-host controller — this
    returns ("all-in-one", None): an entry role, so apply keeps writing ingress
    locally and every existing render stays byte-identical.
    """
    try:
        env = _read_env_file(paths.HOST_ENV)
    except OSError:
        env = {}
    return env.get("ROLE") or "all-in-one", env.get("PRIVATE_IP") or None


def read_tenant() -> str | None:
    """Return TENANT from /etc/nuklaut/host.env (contracts C3).

    None for platform VMs (`TENANT=` empty) and for hosts without the key or the file.
    """
    try:
        env = _read_env_file(paths.HOST_ENV)
    except OSError:
        env = {}
    return env.get("TENANT") or None


# --- the convergence loop ------------------------------------------------------
# One per host, started by the poke (seconds) and by a 6-12 h liveness floor. The
# floor is a LIVENESS GUARANTEE, not a control loop: without it a single lost poke
# — host down during a deploy, service crash, network blip — leaves a host
# silently stale forever (spec §7.2).


@contextmanager
def converge_lock(state_dir: Path) -> Generator[bool]:
    """Hold the whole-cycle lock, yielding False if another run already holds it.

    Non-blocking, and contention is exit 0: a skipped cycle is harmless because
    the next poke or floor picks it up, while a blocking wait would pile up
    systemd jobs. A hand-run `nuk apply` mid-cycle is exactly the race this
    closes — enabling a timer fires its service immediately, which collided with
    a hand-run cycle during layer-1 verification (spec §7 step 1).
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(state_dir / ".lock", os.O_CREAT | os.O_RDWR, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        yield True
    finally:
        os.close(fd)


def archive_tree(repo: Path, commit: str, dest: Path) -> None:
    """Extract `commit` into `dest` — never the live worktree.

    The worktree can carry uncommitted edits mid-session; applying WIP against
    real state on an unattended timer is a landmine (spec §7 step 4). Extraction
    uses tarfile's `data` filter: a tenant repo is untrusted input to a root
    process, and a symlink or `..` member that leaves `dest` must not be created.

    Raises:
        ValueError: If the archive holds a member the `data` filter refuses.
    """
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(  # noqa: S603  # fixed argv, no shell
        ["git", "-C", str(repo), "archive", commit],  # noqa: S607  # git on PATH
        check=True,
        capture_output=True,
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(dest, filter="data")
    except tarfile.TarError as e:
        msg = f"unsafe archive member: {e}"
        raise ValueError(msg) from None


def _provided_capabilities(manifest: Facility) -> set[str]:
    """The capabilities a Facility hands out (its `provides` block)."""
    provides = manifest.spec.provides
    return {p.capability for p in (provides.route, provides.env) if p is not None}


def provision_remote_databases(
    tree: Path,
    role: str,
    facilities: list[Facility],
    *,
    self_ip: str | None = None,
    org: Org | None = None,
) -> list[ManifestResult]:
    """Provision every deployment's databases on this host IF it owns the capability.

    The placement-gate exception (spec §3.1): a deployment placed `app` is a
    no-op on the `data` host for containers and ingress, but its `spec.databases`
    fragment must still be provisioned HERE — this is the only host with a local
    `nuk-postgres`. Scoped to provisioning: nothing else about the manifest runs.

    Deterministic derivation makes this loop-stable: the same seed yields the
    same password, so re-running converges to a no-op rather than rotating.
    """
    provider = env_facility(facilities, _DATABASES_CAPABILITY)
    if provider is None or not placement_matches(provider, role, self_ip=self_ip, org=org):
        return []
    out: list[ManifestResult] = []
    for path in sorted((tree / DEPLOYMENT_DIR).glob("*.yml")):
        try:
            manifest = load(path)
        except SystemExit as e:
            out.append(
                ManifestResult(path.name, "Database", "failed", _exit_reason(e, "load failed"))
            )
            continue
        if manifest.kind != "Deployment":
            continue
        dbs = manifest.spec.databases
        if not (dbs.wants_postgres or dbs.wants_redis):
            continue
        name = manifest.metadata.name
        try:
            # remote_ip=None → the LOCAL data stack is provisioned, on this host.
            provision_databases(name, dbs, facilities, remote_ip=None)
        except (SystemExit, subprocess.CalledProcessError) as e:
            # One app's provisioning failure must not abort the cycle (spec §7.5):
            # `_psql` uses check=True, so a SQL failure (disk full, role/db
            # conflict, container hiccup) surfaces as CalledProcessError, not
            # SystemExit. The data host still writes converge-status.json.
            error = (
                _exit_reason(e, "provision failed")
                if isinstance(e, SystemExit)
                else f"provision failed: {e}"
            )
            out.append(ManifestResult(name, "Database", "failed", error))
            continue
        out.append(ManifestResult(name, "Database"))
    return out


def _exit_reason(e: SystemExit, default: str) -> str:
    """The message a SystemExit carried, or `default` for a bare exit."""
    return str(e.code) if e.code else default


def _deployment_tree(ctx: TreeContext, manifest: Deployment, path: Path) -> Path:
    """The tree one Deployment applies from (Task 11).

    `spec.source.unsigned` opts a non-prod deployment into the branch head, so it
    applies from `ctx.trees["branch"]`; every other deployment keeps the signed tag
    tree (`ctx.tree`). A hand-run apply carries only a tag tree, so a missing branch
    key falls back to `path` rather than raising.
    """
    if not manifest.spec.source.unsigned:
        return path
    branch = ctx.trees.get("branch")
    if branch is None:
        return path
    return branch / path.relative_to(ctx.tree)


def apply_tree(ctx: TreeContext) -> list[ManifestResult]:  # noqa: C901  # placement ambiguity is recorded per manifest, not raised out of the loop
    """Apply this host's Facilities, then its Deployments (spec §7 steps 6-7).

    Facilities first within a cycle (§7.1): effect VOCABULARY is git-derived and
    always resolvable regardless of order, but facility HEALTH needs the facility
    up, and that is same-host. Cross-host ordering is eventual and covered by
    `maintenance-errors@file`.

    One failing manifest never stops the rest (§7.5). `cmd_apply` and `load` both
    signal failure with SystemExit, so each manifest is isolated and its message
    recorded for the status file — a malformed manifest must not take down the
    cycle for every other manifest on the host.

    A facility that fails this cycle POISONS the capabilities it declares:
    a Deployment whose static `consumes()` (§5.3) intersects them is recorded
    "refused" and never applied (§7.5: "Deployments consuming it refuse"). A
    facility placed on another host is skipped before it can fail, and this host
    cannot verify another host's liveness (§13) — only same-host failures refuse.

    Only the kinds named in `ctx.apply` run: a tenant source's `facilities/` is
    never looked at, whatever it contains.

    Args:
        ctx: The source's tree, this host's identity and what the source may change.

    Returns:
        One ManifestResult per manifest this host owns, facilities first, each
        directory in filename order. `result` is "ok", "failed", or "refused".
    """
    tree, role = ctx.tree, ctx.role
    results: list[ManifestResult] = []
    failed_caps: set[str] = set()
    kinds: tuple[tuple[ManifestKind, str], ...] = (
        ("Facility", FACILITY_DIR),
        ("Deployment", DEPLOYMENT_DIR),
    )
    for kind, directory in kinds:
        if directory not in ctx.apply:
            continue
        for path in sorted((tree / directory).glob("*.yml")):
            try:
                manifest = load(path)
            except SystemExit as e:
                results.append(
                    ManifestResult(path.name, kind, "failed", _exit_reason(e, "load failed"))
                )
                continue
            if manifest.kind != kind:
                continue
            try:
                matches = placement_matches(manifest, role, self_ip=ctx.self_ip, org=ctx.org)
            except ValueError as e:
                results.append(ManifestResult(manifest.metadata.name, kind, "failed", str(e)))
                continue
            if not matches:
                continue
            apply_path = path
            if isinstance(manifest, Deployment):
                poisoned = consumes(manifest) & failed_caps
                if poisoned:
                    reason = (
                        f"consumes {sorted(poisoned)} from a facility that "
                        f"failed its health gate this cycle (spec §7.5)"
                    )
                    results.append(ManifestResult(manifest.metadata.name, kind, "refused", reason))
                    continue
                apply_path = _deployment_tree(ctx, manifest, path)
            # A signed (non-unsigned) deployment must BUILD the signed tag, not the
            # branch head its clone would otherwise follow: pin the clone to the
            # tag commit. An unsigned deployment stays on the branch head. A context
            # without a recorded tag commit (hand-run `for_path`, or Task 10's
            # `build()` asymmetry with `commits={}`) degrades to today's behaviour —
            # no pin — rather than raising. (`cmd_apply` refuses a TENANT deployment
            # whose payload repo is not the source's own, so this pin always has the
            # commit it names: a tenant ships its payload in its own repo or in the
            # tree.)
            pin_commit = (
                ctx.commits.get("tag")
                if isinstance(manifest, Deployment) and not manifest.spec.source.unsigned
                else None
            )
            try:
                cmd_apply(apply_path, None, ctx=ctx, pin_commit=pin_commit)
            except (SystemExit, ValueError, subprocess.CalledProcessError, OSError) as e:
                error = _exit_reason(e, "apply failed") if isinstance(e, SystemExit) else str(e)
                results.append(ManifestResult(manifest.metadata.name, kind, "failed", error))
                if isinstance(manifest, Facility):
                    failed_caps |= _provided_capabilities(manifest)
                continue
            results.append(ManifestResult(manifest.metadata.name, kind))
    # The placement exception (spec §3.1) runs in addition to the filter above: a
    # `{placement: app}` deployment is a container/ingress no-op here but its
    # `spec.databases` fragment is still this host's job when it owns the
    # facility. A deployment the loop already produced (applied, refused, failed)
    # was provisioned by `cmd_apply` itself — the sweep must not double it.
    handled = {r.name for r in results if r.kind == "Deployment"}
    results.extend(
        r
        for r in provision_remote_databases(
            tree, role, ctx.facilities, self_ip=ctx.self_ip, org=ctx.org
        )
        if r.name not in handled
    )
    return results


def _declared_names(tree: Path) -> set[str]:
    """`metadata.name` of every manifest file under `tree`, tolerating unreadable ones."""
    names: set[str] = set()
    for directory in (FACILITY_DIR, DEPLOYMENT_DIR):
        for path in (tree / directory).glob("*.yml"):
            raw = _read_yaml_safe(path)
            meta = raw.get("metadata") if isinstance(raw, dict) else None
            if isinstance(meta, dict) and meta.get("name"):
                names.add(str(meta["name"]))
    return names


def reap_report(*trees: Path) -> list[str]:
    """Names deployed on this host but declared by none of `trees` (spec §7.4).

    Reports; never deletes. Auto-prune would make an accidental `git rm hello.yml`
    an outage, while an orphan stays visible via `nuk status` and `drift.sh` and
    is recoverable — a pruned production app is not.

    Facilities count as declared: a facility's project dir sits in DEPLOYS beside
    the deployments, and calling it an orphan would warn on every cycle. Pass every
    source's tree of the cycle — a host runs the platform's facilities AND its own
    tenant's deployments.
    """
    if not paths.DEPLOYS.is_dir():
        return []
    declared: set[str] = set()
    for tree in trees:
        declared |= _declared_names(tree)
    return sorted(p.name for p in paths.DEPLOYS.iterdir() if p.is_dir() and p.name not in declared)


def write_converge_status(  # noqa: PLR0913  # one status field per keyword; a dataclass buys nothing here
    path: Path,
    *,
    role: str,
    tenant: str | None,
    sources: dict[str, SourceBlock],
    warnings: list[str],
    logging: LoggingStatus | None = None,
    error: str | None = None,
) -> None:
    """Record the cycle's outcome (spec §7.6, contracts C3).

    `sources` maps each source name to its block. `logging` is the LOGGING pipeline's own health —
    info-only (spec §14.3): recorded, never a per-manifest result, never a failure
    condition; absent for non-edge cycles. `error` is set when the cycle could not even
    start (an unreadable sources.yml), so a failure is still a status, not silence.

    Consumed by `drift.sh` and by `nuk status`.
    """
    status = ConvergeStatus(
        role=role,
        tenant=tenant,
        applied_at=_iso_utc_now(),
        reap_warnings=warnings,
        sources=sources,
        logging=logging,
        error=error,
    )
    _atomic_write(path, json.dumps(status.to_wire(), indent=2) + "\n")


def read_converge_status(path: Path = paths.CONVERGE_STATUS) -> ConvergeStatus | None:
    """The last recorded cycle, or None if absent/unreadable/malformed."""
    return ConvergeStatus.from_wire(_read_json_safe(path))


_SOURCE_FAILURES = (ValueError, SystemExit, subprocess.CalledProcessError, OSError)


def _prepare_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: SourceEntry,
    block: SourceBlock,
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
    scratch: Path,
    platform: Path | None,
) -> TreeContext:
    """Sync, verify and archive one source and build its context; fill tag/commit in `block`.

    Both refs are archived: the signed tag's tree under `tag` and the branch head's
    under `branch`. `ctx.tree` remains the tag tree (what a signed deployment
    applies); Task 11's per-deployment selection reads `ctx.trees`. Only the tag
    path is downgrade-guarded (`sync_source`).

    Raises:
        ValueError: With the refusal reason (also CalledProcessError/OSError/SystemExit from
            the git and manifest layers — `_SOURCE_FAILURES`).
    """
    if not src.is_platform and platform is None:
        msg = (
            "the platform source did not verify this cycle — no facilities or org to apply against"
        )
        raise ValueError(msg)
    tag, tag_sha, branch_sha = sync_source(src, signers_dir, state_dir)
    block.tag, block.commit = tag, tag_sha
    print(f"target: {src.name} {tag} ({tag_sha[:12]}) role={role}")
    repo = source_state_dir(state_dir, src.name) / "repo"
    tag_tree = scratch / src.name / "tag"
    branch_tree = scratch / src.name / "branch"
    archive_tree(repo, tag_sha, tag_tree)
    archive_tree(repo, branch_sha, branch_tree)
    tenant = None if src.is_platform else src.name
    return TreeContext.build(
        tag_tree,
        role,
        self_ip,
        tenant,
        frozenset(src.apply),
        platform=platform,
        trees={"tag": tag_tree, "branch": branch_tree},
        commits={"tag": tag_sha, "branch": branch_sha},
        source_repo=src.repo,
    )


def _apply_source(
    src: SourceEntry, ctx: TreeContext, block: SourceBlock, state_dir: Path, auth: HostAuth
) -> None:
    """Apply a prepared source: manifests, then routes; record it applied only if all went well."""
    block.manifests = apply_tree(ctx)
    if "routes" in src.apply and ctx.role in _ENTRY_ROLES:
        routes = render_routes(ctx, auth)
        block.rendered = routes.rendered
        block.refused_routes = routes.refused
    # _prepare_source always sets both before a source reaches the apply pass.
    assert block.tag is not None  # noqa: S101  # narrows the union for ty
    assert block.commit is not None  # noqa: S101  # narrows the union for ty
    record_applied(
        block.tag, block.commit, source_state_dir(state_dir, src.name) / "last-applied-tag"
    )


def _refuse(src: SourceEntry, block: SourceBlock, e: BaseException) -> None:
    block.result = "refused"
    block.error = _exit_reason(e, "converge refused") if isinstance(e, SystemExit) else str(e)
    print(f"REFUSING source {src.name}: {block.error}", file=sys.stderr)


def _converge_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: SourceEntry,
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
    scratch: Path,
    platform: Path | None,
) -> tuple[SourceBlock, TreeContext | None]:
    """PREPARE one source (sync/verify/archive); never raises for a source-level failure.

    The apply step moved to `_run_cycle`'s second pass so every source's tree is known
    before any renders (a delegation must be honoured in the cycle it lands, spec §3.5).

    Returns:
        The source's status block, and its TreeContext once the tree is verified and archived
        (None when that failed, or when the platform tree is incomplete) — the platform's
        context is what tenant sources build on. `result` is "refused" on any failure here.
    """
    block = SourceBlock(apply=[str(a) for a in src.apply])
    try:
        ctx = _prepare_source(
            src,
            block,
            role=role,
            self_ip=self_ip,
            signers_dir=signers_dir,
            state_dir=state_dir,
            scratch=scratch,
            platform=platform,
        )
        if src.is_platform and ctx.org is None:
            msg = (
                f"the platform tree at {block.tag} lacks {DEFAULT_ORG_FILE} — "
                f"backends and routes resolve from it and cannot be guessed"
            )
            raise ValueError(msg)  # noqa: TRY301  # same refusal path as every other failure here
    except _SOURCE_FAILURES as e:
        _refuse(src, block, e)
        return block, None
    return block, ctx


class _UnknownAuthorizationError(NukError):
    """The cycle's authorization set could not be built, so it must not apply (spec §4).

    Raised when a refused owner's last-verified cache is unreadable: the loan set is
    unknown, so silently dropping it would let lent names vanish. The cycle records the
    failure and does not run the apply pass.
    """


def _load_prepared_delegations(
    prepared: list[tuple[SourceEntry, TreeContext]],
    *,
    blocks: dict[str, SourceBlock],
) -> tuple[dict[str, list[Delegation]], list[tuple[SourceEntry, TreeContext]]]:
    """Load each routable prepared owner's `delegations.yml`, refusing a malformed one (spec §2).

    Only sources with `routes` in `apply` contribute (spec §2). A malformed manifest is
    attributable, so it refuses THAT source alone: its loans are never added to the returned
    map, it drops out of the caller's authorization set, and the rest of the fleet proceeds.

    Returns:
        The owner loans loaded so far and the prepared sources still in play.
    """
    delegations: dict[str, list[Delegation]] = {}
    keep: list[tuple[SourceEntry, TreeContext]] = []
    for src, ctx in prepared:
        if ctx.tenant is None or "routes" not in src.apply:
            keep.append((src, ctx))
            continue
        try:
            delegations[ctx.tenant] = load_delegations(ctx.tree)
        except _SOURCE_FAILURES as e:
            _refuse(src, blocks[src.name], e)
            continue
        keep.append((src, ctx))
    return delegations, keep


def _cached_delegations(state_dir: Path, owner: str) -> list[Delegation]:
    """`owner`'s last-verified loans; a corrupt cache is a recorded cycle failure (spec §4).

    A refused owner lends its cache so a foreign fetch failure cannot pull a lent name away.
    If that cache is unreadable the loan set is UNKNOWN — dropping it would silently withdraw
    lent names — so this raises `_UnknownAuthorizationError` (carrying the reason) for the caller
    to record, rather than degrading to an empty loan set.
    """
    try:
        return load_cached_delegations(state_dir, owner)
    except NukError as e:
        raise _UnknownAuthorizationError(_exit_reason(e, "cached delegations unreadable")) from e


def _refuse_bad_declarations(
    prepared: list[tuple[SourceEntry, TreeContext]],
    refused: list[SourceEntry],
    registry: TenantRegistry,
    delegations: dict[str, list[Delegation]],
    *,
    blocks: dict[str, SourceBlock],
) -> list[tuple[SourceEntry, TreeContext]]:
    """Refuse each source whose declarations do not validate; return the survivors.

    `validate_delegations` and `check_cross_zone_patterns` judge one tenant at a time, so
    a violation refuses THAT source — its loans are dropped from `delegations` and the rest
    of the fleet proceeds — instead of aborting the whole cycle (spec §2). A loan judged
    against a bad declaration is therefore never honoured, so fail-closed holds. An
    already-refused source whose cached loan is invalid is simply not honoured, never a
    second refusal.
    """
    surviving: list[tuple[SourceEntry, TreeContext]] = []
    for src, ctx in prepared:
        if ctx.tenant is None:
            surviving.append((src, ctx))
            continue
        dels = delegations.get(ctx.tenant, [])
        try:
            if dels:
                validate_delegations(ctx.tenant, dels, registry)
            check_cross_zone_patterns(ctx.tenant, registry, delegations)
        except _SOURCE_FAILURES as e:
            _refuse(src, blocks[src.name], e)
            delegations.pop(ctx.tenant, None)
            continue
        surviving.append((src, ctx))
    for src in refused:
        if src.is_platform or "routes" not in src.apply:
            continue
        dels = delegations.get(src.name, [])
        if not dels:
            continue
        try:
            validate_delegations(src.name, dels, registry)
        except _SOURCE_FAILURES:
            delegations.pop(src.name, None)
    return surviving


def _host_auth(
    platform_ctx: TreeContext | None,
    prepared: list[tuple[SourceEntry, TreeContext]],
    *,
    state_dir: Path,
    refused: list[SourceEntry],
    blocks: dict[str, SourceBlock],
) -> tuple[HostAuth, list[tuple[SourceEntry, TreeContext]]]:
    """Build the cycle's host authorization from the registry and every owner's loans.

    The registry is the platform tree's `tenants.yml`; without one no tenant owns
    anything and every tenant render is refused (fail-closed, spec §3.4). Only sources
    with `routes` in `apply` contribute loans (spec §2). Each such prepared tenant source
    lends from its own `delegations.yml`; a REFUSED one instead lends its last VERIFIED
    loans from the cache, so a foreign fetch failure cannot pull a lent name away (spec §4).

    Validation is per source (`_refuse_bad_declarations`): a violation refuses THAT source
    — its loans are dropped and the rest of the fleet proceeds — instead of aborting the
    whole cycle (spec §2). A malformed `delegations.yml` refuses its source the same way
    (`_load_prepared_delegations`); only an unreadable cache for a refused owner — which
    would make the loan set unknown — raises `_UnknownAuthorizationError` for the caller.

    Returns:
        The authorization and the prepared sources that survived validation (the ones the
        caller may apply). A validation-refused source's block is filled via `_refuse`.
        Only surviving, routable owners have their verified state written back to the cache.

    Raises:
        _UnknownAuthorizationError: When a refused owner's cached loans cannot be read (spec §4).
    """
    registry = platform_ctx.tenants if platform_ctx is not None else None
    if registry is None:
        registry = TenantRegistry(tenants=[])
    delegations, prepared_ok = _load_prepared_delegations(prepared, blocks=blocks)
    for src in refused:
        # Without a verified platform tree there is no registry to authorize against, so
        # the cache would add nothing but a spurious "not in the registry" refusal.
        if not src.is_platform and "routes" in src.apply and platform_ctx is not None:
            delegations[src.name] = _cached_delegations(state_dir, src.name)
    surviving = _refuse_bad_declarations(prepared_ok, refused, registry, delegations, blocks=blocks)
    for src, ctx in surviving:
        if ctx.tenant is not None and "routes" in src.apply:
            store_delegations(state_dir, ctx.tenant, delegations[ctx.tenant])
    return HostAuth(registry, delegations), surviving


def _logging_status(role: str, platform_ctx: TreeContext | None) -> LoggingStatus | None:
    """The LOGGING pipeline's own health (spec §14.3): info-only, edge cycles only."""
    if role != "edge" or platform_ctx is None:
        return None
    facility = env_facility(platform_ctx.facilities, "logs")
    if facility is None:
        return None
    reason = facility_health(facility)
    return LoggingStatus(healthy=reason is None, detail=reason or "ok")


def _run_cycle(  # noqa: PLR0913  # one keyword per cycle input
    sources: list[SourceEntry],
    blocks: dict[str, SourceBlock],
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
) -> tuple[list[str], LoggingStatus | None, bool, str | None]:
    """Converge every source, platform first; fill `blocks`.

    Two passes: first PREPARE every source (fetch/verify/archive) and keep its context, so
    all of a cycle's trees — and thus every owner's delegations.yml — are known before any
    render; then build the host authorization (spec §3) and APPLY each prepared source
    against it. A delegation declared by a later source is therefore effective in the same
    cycle (spec §3.5). Building the authorization also validates each source's declarations
    and refuses the offending source alone — a bad loan or malformed manifest never halts
    the fleet, but the cycle still ends not clean (spec §2). An unreadable cache for a
    refused owner instead makes the authorization set unknown: the apply pass is skipped
    and the failure is returned so the caller records it (spec §4).

    Returns:
        (orphan warnings, logging status, whether every source converged, cycle-level error
        — non-None only when the authorization set could not be built).
    """
    with tempfile.TemporaryDirectory(dir=state_dir, prefix="run.") as scratch:
        prepared: list[tuple[SourceEntry, TreeContext]] = []
        refused: list[SourceEntry] = []
        platform_ctx: TreeContext | None = None
        for src in sources:
            blocks[src.name], ctx = _converge_source(
                src,
                role=role,
                self_ip=self_ip,
                signers_dir=signers_dir,
                state_dir=state_dir,
                scratch=Path(scratch),
                platform=platform_ctx.tree if platform_ctx else None,
            )
            if ctx is not None:
                prepared.append((src, ctx))
                platform_ctx = ctx if src.is_platform else platform_ctx
            else:
                refused.append(src)
        auth: HostAuth | None = None
        applied: list[tuple[SourceEntry, TreeContext]] = []
        cycle_error: str | None = None
        try:
            auth, applied = _host_auth(
                platform_ctx, prepared, state_dir=state_dir, refused=refused, blocks=blocks
            )
        except _UnknownAuthorizationError as e:
            # The loan set is unknown; running the apply pass on it would be unsound.
            cycle_error = _exit_reason(e, "authorization unavailable")
            print(f"REFUSING cycle: {cycle_error}", file=sys.stderr)
        if auth is not None:
            for src, ctx in applied:
                try:
                    _apply_source(src, ctx, blocks[src.name], state_dir, auth)
                except _SOURCE_FAILURES as e:
                    _refuse(src, blocks[src.name], e)
        trees = [ctx.tree for _src, ctx in applied]
        clean = cycle_error is None and all(b.result == "ok" for b in blocks.values())
        # A refused source has no tree this cycle, so its apps would all read as orphans;
        # only a clean cycle can tell what is really undeclared.
        warnings = reap_report(*trees) if clean else []
        return warnings, _logging_status(role, platform_ctx), clean, cycle_error


def cmd_converge(*, sources_file: Path, signers_dir: Path, state_dir: Path) -> int:
    """Converge this host from every source in `sources_file` (contracts C3).

    The platform source goes first. Each source is fetched with its own deploy key, verified
    against its own signers file, downgrade-guarded and archived separately; one source
    refusing never stops another — except that tenant sources build on the platform tree, so
    they are refused (with that reason) when the platform source did not verify.
    The status file is written on every exit path after the lock, including a failure.

    Returns:
        0 when every source converged or the lock was held; 1 when any source was refused.
    """
    with converge_lock(state_dir) as acquired:
        if not acquired:
            print("another converge run holds the lock; skipping this cycle")
            return 0
        role, self_ip = read_self()
        blocks: dict[str, SourceBlock] = {}
        warnings: list[str] = []
        logging_status: LoggingStatus | None = None
        error: str | None = None
        code = 1
        sources: list[SourceEntry] = []
        try:
            sources = load_sources(sources_file).ordered()
        except ValueError as e:
            error = str(e)
            print(f"REFUSING: {error}", file=sys.stderr)
        try:
            if sources:
                warnings, logging_status, clean, cycle_error = _run_cycle(
                    sources,
                    blocks,
                    role=role,
                    self_ip=self_ip,
                    signers_dir=signers_dir,
                    state_dir=state_dir,
                )
                code = 0 if clean else 1
                error = cycle_error or error
        finally:
            write_converge_status(
                state_dir / "converge-status.json",
                role=role,
                tenant=read_tenant(),
                sources=blocks,
                warnings=warnings,
                logging=logging_status,
                error=error,
            )
        if warnings:
            print(
                f"WARN: {len(warnings)} deployed app(s) not declared by any source: "
                f"{', '.join(warnings)}\n"
                f"      This loop never removes deployments. Retire explicitly:  "
                f"nuk delete <name>"
            )
        return code


def placement_matches(
    manifest: Deployment | Facility,
    role: str,
    *,
    self_ip: str | None = None,
    org: Org | None = None,
) -> bool:
    """Whether THIS host, with `role` at `self_ip`, runs `manifest`.

    The convergence loop hands every host the same tree; each applies the subset
    it owns. A manifest placed elsewhere is another host's job, not an error —
    hence a clean no-op rather than a failure (spec §5.4).

    Two documented exceptions match:
      * no `placement` at all — a manifest written before placement existed.
        It applies wherever it is run, exactly as it did before.
      * role `all-in-one` — a real composition of edge + data + app (spec §3.1),
        so it owns every placement.

    `placement.host` pins a manifest to one named host: it matches only where that
    host's `privateIp == self_ip`, and a pin naming a host the org does not declare
    is a loud error. A Deployment placed `app` with no `host` resolves to the org's
    default app host once the org has more than one app host; without a default it
    is a loud error, never a silent double-deploy. A Facility is shared substrate
    and matches every host of its role (each app host runs its own `router`).
    """
    placement = manifest.spec.placement
    if placement is None or role == "all-in-one":
        return True
    if placement.role != role:
        return False
    if placement.host is not None:
        if org is None:
            return False
        host = org.host_named(placement.host)
        if host is None:
            msg = (
                f"{manifest.metadata.name}: placement.host={placement.host!r} — the org "
                f"manifest declares no host of that name."
            )
            raise ValidationError.from_exception_data(
                manifest.metadata.name,
                [
                    {
                        "type": "value_error",
                        "loc": ("spec", "placement", "host"),
                        "input": placement.host,
                        "ctx": {"error": ValueError(msg)},
                    }
                ],
            )
        return host.private_ip == self_ip
    if isinstance(manifest, Deployment) and role == "app" and org is not None:
        count = org.app_host_count()
        if count > 1 and org.default_host("app") is None:
            msg = (
                f"{manifest.metadata.name}: placement.role='app' is ambiguous — the org has "
                f"{count} app hosts and none is the default; set spec.placement.host to pin one."
            )
            # `ValidationError` is pydantic's (a ValueError, so `apply_tree`'s failure
            # guard catches it); in v2 it cannot be raised with a bare message, so
            # build one carrying `msg` through the supported constructor.
            raise ValidationError.from_exception_data(
                manifest.metadata.name,
                [
                    {
                        "type": "value_error",
                        "loc": ("spec", "placement", "host"),
                        "input": None,
                        "ctx": {"error": ValueError(msg)},
                    }
                ],
            )
        default = org.default_host("app")
        return default is None or default.private_ip == self_ip
    return True


def _render_routers(
    tree: Path,
    org: Org,
    *,
    tenant: str | None,
    auth: HostAuth | None,
    platform_facilities: list[Facility] | None = None,
) -> RouteResult:
    """On the edge: render a router for EVERY Deployment with ingress (spec §6).

    Cross-host router delivery is gone. The edge reads the same git tree every
    host reads and resolves each backend from the org manifest, so the app host
    authors nothing that reaches the edge (spec §6, §6.3).

    Stale routers for retired apps are NOT removed here — a manifest disappearing
    from git is destructive, and the loop reports rather than deletes (spec §7.4).
    The one bounded exception is the legacy `worker-` prefix (reap_legacy_worker_routers).

    A tenant source's router set is authoritative (spec §5): a render that allows none
    of a deployment's hosts withdraws the file it wrote before, rather than leaving a
    lent host live — revocation. The withdrawal is keyed by the deployment's NAME (the
    router file name), not by source: a fleet-wide deployment-name collision would
    therefore touch a file another source wrote. The surrounding system discourages
    cross-source name collisions, but this path does not itself detect them.

    Args:
        tree: Root of the manifest tree the loop pulled.
        org: The validated org manifest, source of every backend private IP.
        tenant: The source's tenant name, or None for the platform source.
        auth: The cycle's host authorization (spec §3), consulted only for a tenant
            source: an ingress whose host resolves to anyone but `tenant` is REFUSED —
            recorded, never written. The `www.<host>` variant (spec §6) is resolved the
            same way and is omitted when it is not covered, leaving the apex router. None
            with a tenant present refuses every host (fail-closed); None with tenant None
            is the ungated platform render.
        platform_facilities: The PLATFORM tree's facilities, when the caller has
            them (a tenant source ships none). The fleet-wide `router` lives in
            the platform source, so `router_present` must be read from here — not
            from `tree`, which in the S1 topology holds only this source's
            deployments. Falls back to `tree`'s own facilities when empty, so a
            caller that does not plumb them keeps the old behaviour.

    Returns:
        The router names written and the refusal lines (one per foreign host).
    """
    paths.DYNAMIC.mkdir(parents=True, exist_ok=True)
    deployments = load_deployments(tree)
    protected = {f"{m.metadata.name}.yml" for m in deployments}
    for stale in reap_legacy_worker_routers(protected):
        print(f"edge: reaped legacy router {stale} (cross-host delivery is retired)")
    facilities = load_facilities(tree)
    vocab = route_vocabulary(facilities)
    router_present = _router_present(platform_facilities or facilities)
    rendered: list[str] = []
    refused: list[str] = []
    for manifest in deployments:
        ingress = manifest.spec.ingress
        if not ingress:
            continue
        # A deployment placed on an entry host runs ALONGSIDE Traefik, so
        # cmd_apply already rendered its router there with a container-name
        # backend. Re-rendering it from here would overwrite that working file
        # with a `privateIp:port` backend nothing is listening on.
        placement = manifest.spec.placement
        if placement is not None and placement.role in _ENTRY_ROLES:
            continue
        if tenant is not None:
            allowed = _authorized_ingress(ingress, tenant, auth, refused)
            if not allowed:
                # Revocation (spec §5): the owner's router set is authoritative, so a
                # render that allows none of the deployment's hosts withdraws the file
                # it wrote before. The withdrawal is keyed by the deployment's name, so a
                # fleet-wide name collision would touch another source's router — the
                # system discourages that, but this path does not detect it.
                write_ingress(manifest.metadata.name, [], vocab)
                continue
            ingress = allowed
        resolved = [
            ing.model_copy(
                update={
                    "address": backend_address(org, manifest, ing, router_present=router_present),
                    "service": None,
                    "port": None,
                    "host_port": None,
                }
            )
            for ing in ingress
        ]
        name = manifest.metadata.name
        write_ingress(name, resolved, vocab)
        rendered.append(name)
    return RouteResult(rendered, refused)


def render_routes(ctx: TreeContext, auth: HostAuth | None = None) -> RouteResult:
    """On the edge: render ONE source's routers through the host authorization (spec §3).

    The platform source (ctx.tenant is None) is unconstrained — it owns the platform
    domains. A tenant source renders only the hosts `auth` names as its own; without an
    authorization it renders nothing (fail-closed).
    """
    if ctx.org is None:
        return RouteResult([], [])
    return _render_routers(
        ctx.tree,
        ctx.org,
        tenant=ctx.tenant,
        auth=auth,
        platform_facilities=ctx.facilities,
    )


def consumes(manifest: Deployment) -> set[str]:
    """The capabilities this Deployment consumes, derived from its own fields.

    Static consumption (spec §5.3) — the map is a literal lookup, and adding a
    capability adds a row:

    | Deployment field        | Consumes                   |
    |--------------------------|----------------------------|
    | `databases:`            | env capability `databases` |

    A Deployment consuming nothing still gets the default `tls` route from the
    ingress facility; `tls` is substrate, not consumption. Plan 3's loop uses
    this to refuse the consumers of a facility that failed its health gate
    (§7.5) without any runtime state.

    Args:
        manifest: The Deployment being considered.

    Returns:
        The capability names consumed; empty for none.
    """
    caps: set[str] = set()
    db = manifest.spec.databases
    if db.postgres or db.redis:
        caps.add(_DATABASES_CAPABILITY)
    return caps


# --- provenance-on-apply -------------------------------------------------------
# `nuk apply` appends the exact commit/image it deployed to
# /var/lib/nuk/releases/<name>.jsonl, one JSON object per line, so `status` has a
# trustworthy source even for rsync-mirrored (.git-less) workflow deploys.
# Best-effort by design: see the try/except around its only call site in cmd_apply.
#
# It was a single object at DEPLOYS/<name>/provenance.json until 0.18 — a record,
# not a history, overwritten on every apply (spec §8). The file moved to
# /var/lib/nuk/releases so it survives a VM rebuild on the host's data volume
# (same store family as Loki chunks, §14.4); a legacy provenance.json is READ as a
# seed, never written. Appending is what makes `nuk rollback` possible at all, and
# it is the one genuinely valuable idea in Helm, in better shape than Helm's.

# Releases kept per deployment (spec §8: the last 20). A bound, not a policy:
# the file is read whole on every apply, and an operator choosing a rollback

# --- command layer ------------------------------------------------------------
# Commands read typed scalars off the validated Manifest but pass its raw dict
# (manifest.raw / manifest.raw["spec"]) to the wire-contract render functions.


_FACILITY_GROUP = "nuk-facility"


def _is_privileged() -> bool:
    """Whether the caller may apply a Facility.

    One binary, authority derived from the caller — the `systemctl` model
    (spec §4.4). A second binary would give zero isolation: same host, same
    user, same filesystem.

    Root, or membership in `nuk-facility`. A missing or broken group is not an
    error — it means the capability cannot be resolved, so only root qualifies.
    """
    if os.geteuid() == 0:
        return True
    try:
        gid = grp.getgrnam(_FACILITY_GROUP).gr_gid
    except (KeyError, OSError):
        return False
    return gid in os.getgroups()


def _repo_identity(url: str) -> str:
    """A repo URL reduced to `host/owner/name`, so transport forms compare equal."""
    s = url.strip().rstrip("/")
    if "://" in s:
        s = s.split("://", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[1]
    s = s.replace(":", "/", 1)  # scp-style `host:owner/name`
    return s.removesuffix(".git").rstrip("/").lower()


def _same_repo(left: str | None, right: str | None) -> bool:
    """Whether two manifests name the same repo; `None` (a sourceless payload) never matches."""
    return left is not None and right is not None and _repo_identity(left) == _repo_identity(right)


def cmd_apply(  # noqa: C901, PLR0912, PLR0914, PLR0915  # linear apply pipeline; splitting it would scatter the reconcile order
    manifest_path: Path,
    repo_path: str | None,
    *,
    ctx: TreeContext | None = None,
    pin_commit: str | None = None,
    pin_digest: str | None = None,
) -> None:
    """Create or update a deployment from a manifest.

    Args:
        manifest_path: Path to the nuk/v1 manifest.
        repo_path: Local checkout to mirror instead of cloning spec.source.repo.
        ctx: The converge loop's prepared context; a hand-run apply builds its own
            from the manifest's tree and this host's identity.
        pin_commit: Check the source repo out DETACHED at this commit instead of
            following spec.source.branch. Set only by `cmd_rollback` (spec §8).
        pin_digest: Pull this image digest and re-tag it over the compose file's
            own image reference for the same repository, so `up -d` recreates
            the service with exactly the recorded bits. Set only by
            `cmd_rollback`; fails closed (spec §8).
    """
    manifest_path = resolve_manifest(manifest_path)
    manifest = load(manifest_path)
    name = manifest.metadata.name
    if manifest.kind == "Facility" and not _is_privileged():
        print(
            f"{name}: Facility apply requires root or membership in group "
            f"{_FACILITY_GROUP!r} (spec §4.4). Refusing."
        )
        sys.exit(1)
    ctx = ctx or TreeContext.for_path(manifest_path)
    role, self_ip = ctx.role, ctx.self_ip
    if not placement_matches(manifest, role, self_ip=self_ip, org=ctx.org):
        # placement_matches returns False only when a placement is set and differs.
        placement = manifest.spec.placement
        assert placement is not None  # noqa: S101  # narrows the union for ty
        print(
            f"{name}: spec.placement.role={placement.role!r} but this host "
            f"is role={role!r} — nothing to do"
        )
        return
    facilities = ctx.facilities
    vocab = route_vocabulary(facilities) if facilities else DEFAULT_ROUTE_VOCAB
    # Router mode (C1): the fleet runs the `router` facility, which is placed on an
    # app host and terminates HTTP on the private `mesh` entrypoint — no TLS, no
    # edge `global.yml`. This host therefore writes its app file router in the mesh
    # dialect. The gate on `role == "app"` keeps an entry host (which sits alongside
    # the edge Traefik and still renders edge-dialect routers) on the edge dialect.
    #
    # A facilities-less context — a hand-run apply, or the digest-path re-apply
    # `cmd_rollback` drives through `cmd_apply(..., ctx=None)` — cannot see the
    # platform `router` facility (the persisted manifest dir ships no facilities/).
    # Fall back to the dialect the last apply recorded (Task 16) so a router-mode app
    # keeps its app-host file router instead of unlinking it below; an unrecorded app
    # reads `edge` and keeps the legacy behaviour.
    router_present = _router_present(facilities)
    if not facilities:
        router_present = router_dialect(name) == "mesh"
    router_mode = role == "app" and router_present
    # Only the mesh write carries the dialect; the edge-dialect call stays
    # byte-identical to what every existing caller and test double expects.
    mesh_kwargs = {"dialect": "mesh"} if router_mode else {}
    paths.DYNAMIC.mkdir(parents=True, exist_ok=True)
    paths.DEPLOYS.mkdir(parents=True, exist_ok=True)
    source = manifest.spec.source
    if ctx.tenant is not None and source.repo and not _same_repo(source.repo, ctx.source_repo):
        # The tree is the review unit (P1): a tenant source may ship its compose payload
        # under deployments/<name>/, or name the tenant's OWN repo — the one whose signed
        # tag this cycle verified. Naming any other repo would have the app host clone it
        # as root with ambient credentials, and the signed-tag pin could never resolve
        # there. Refuse before anything is fetched.
        die(
            f"{manifest_path}: a tenant source may only name its own repo "
            f"({ctx.source_repo}), or ship its compose payload under deployments/{name}/ — "
            f"{source.repo!r} is not allowed"
        )
    # A declaration-only Facility (e.g. facilities/basic.yml)
    # provides a route capability and nothing else: no source to clone, no
    # compose payload to mirror, no services to bring up. Applying it is pure
    # vocabulary registration, so demanding a facilities/<name>/ payload it has
    # no use for would refuse a perfectly valid manifest. A sourceless Facility
    # that DOES declare spec.compose (data-stack, ingress) still needs one.
    declaration_only = (
        manifest.kind == "Facility"
        and not repo_path
        and not source.repo
        and not manifest.spec.compose.model_fields_set
    )
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
        elif pin_commit:
            sh("git", "-C", str(repo), "fetch", "--quiet")
        else:
            sh("git", "-C", str(repo), "checkout", branch)
            sh("git", "-C", str(repo), "pull", "--ff-only", "--quiet")
        if pin_commit:
            # Rollback. The branch checkout + ff-only pull above is skipped rather
            # than followed by a detach, because pulling first would fetch the very
            # tip we are rolling away from and leave the tree at it if the detach
            # then failed.
            sh("git", "-C", str(repo), "checkout", "--quiet", "--detach", pin_commit)
    elif declaration_only:
        pass  # nothing to mirror — the manifest IS the whole facility
    else:
        # A sourceless manifest — a Facility like data-stack, or a Deployment whose
        # compose ships with the tree — carries its payload beside its manifest at
        # <tree>/facilities|deployments/<name>/ (the manifest's own directory is the
        # tree root for a hand-run apply, the archive root for the loop). Mirror it
        # into the project dir exactly like a cloned repo, so compose_args' existing
        # `-f repo/<file>` resolution works unchanged. rsync --delete converges
        # repo/ in place: removing it first would hand running containers a new
        # inode under their bind mounts on every cycle.
        payload = manifest_path.resolve().parent / name
        if not payload.is_dir():
            where = f"{manifest_path.resolve().parent.name}/{name}/"
            die(
                f"{manifest_path}: {manifest.kind} {name} has no source.repo and no "
                f"{where} payload directory — nothing to apply"
            )
        sh("rsync", "-a", "--delete", f"{payload}/", str(repo) + "/")
    if pin_digest:
        _pin_image(name, manifest.spec, pin_digest)
    ingress = manifest.spec.ingress
    org = ctx.org
    remote_ip = None
    if org is not None:
        # The remote decision mirrors provision_remote_databases's owner gate
        # exactly (spec §3.1): this host provisions locally iff it owns the
        # `databases` capability. Keying on `role != "data"` diverges for an
        # all-in-one host, which placement_matches treats as owner of every
        # facility — the two sides must never disagree.
        owner = env_facility(facilities, _DATABASES_CAPABILITY)
        owns_databases = owner is not None and placement_matches(
            owner, role, self_ip=self_ip, org=org
        )
        if not owns_databases:
            remote_ip = data_host_ip(org)
    db_env = provision_databases(name, manifest.spec.databases, facilities, remote_ip=remote_ip)
    db_services = resolve_db_services(name, manifest.spec, db_env)
    if db_env and not db_services:
        print(
            f"{name}: databases provisioned but no service to attach them to — "
            f"DATABASE_URL/REDIS_URL won't be injected. Add an ingress entry, or set "
            f"spec.databases.attachTo / attachAll to target a worker."
        )
    env_from = resolve_env_from(manifest.spec)
    if env_from and not ingress:
        print(
            f"{name}: spec.envFrom secrets resolved but no ingress service to "
            f"attach them to — they won't be injected. Add an ingress entry."
        )
    # The edge renders EVERY router from the git tree (spec §6), so a non-edge host
    # no longer authors anything for it. It still PUBLISHES its container port on
    # its private IP — that is the backend the edge's router points at.
    edge_term = role not in _ENTRY_ROLES and bool(ingress)
    if edge_term and self_ip is None:
        die(
            f"{name}: host is non-edge (role={role}) but /etc/nuklaut/host.env has no "
            f"PRIVATE_IP — cannot publish ingress for the edge to reach"
        )
    strategy = manifest.spec.strategy
    # Router mode (C3): the app host's own router resolves each backend by its
    # compose DNS name over the shared `edge` network, so the colour containers
    # must JOIN `edge` — not publish a host port the router cannot dial. A
    # blue-green deployment's services are profile-suffixed `<service>-<colour>`;
    # wire BOTH colours so whichever the rollout flips to is reachable, including
    # the colour a later rollback brings back up (rollback does not rewrite this
    # file). A non-blue-green router-mode app keeps its base service keys.
    router_colours = (
        ["blue", "green"]
        if router_mode and strategy is not None and strategy.type == "blue-green"
        else None
    )
    write_override(
        name,
        ingress,
        db_env,
        env_from,
        db_services,
        publish_ip=self_ip if (edge_term and not router_mode) else None,
        local_data=remote_ip is None,
        colours=router_colours,
    )
    migrate = manifest.spec.migrate
    if manifest.kind == "Deployment" and migrate is not None and pin_digest is None:
        # Before the rollout. A digest-path rollback (`pin_digest`, set only by
        # `cmd_rollback`) never migrates — forward-only, and the recorded
        # revision it restores may predate the current migration head. A
        # blue-green colour flip never reaches here at all.
        key = _rollout_key(name, manifest.spec, migrate, strategy)
        if key is None or key != migrated_digest(name):
            _run_migrations(name, manifest.spec, migrate, strategy, key)
    if strategy is not None and strategy.type == "blue-green":
        # Blue-green replaces "ingress -> up -d" with a colour rollout: bring the
        # idle colour up (its compose profile), gate on its health, flip the
        # app-host file router to it, record it, then drain the old colour. The
        # app host owns its own router here (the edge routes stably to it), so
        # the colourless `edge_term` unlink below is deliberately bypassed.
        persist_manifest(manifest.spec, manifest_path, pdir / "manifest.yml", repo_path)
        _apply_blue_green(name, manifest.spec, ingress, vocab, strategy, **mesh_kwargs)
    else:
        if edge_term and not router_mode:
            _router_file(name).unlink(missing_ok=True)  # inert here; the edge owns it
        else:
            write_ingress(name, ingress, vocab, **mesh_kwargs)
        # Record the dialect this apply decided (write OR unlink) so a later
        # facilities-less re-apply — the digest-path rollback — re-decides router mode
        # from the marker rather than guessing `edge` and unlinking the app-host router.
        record_router_dialect(name, "mesh" if router_mode else "edge")
        persist_manifest(manifest.spec, manifest_path, pdir / "manifest.yml", repo_path)
        # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
        # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
        # whose image id changed. A declaration-only Facility has no compose file at
        # all — there is nothing to bring up.
        if not declaration_only:
            sh(*compose_args(name, manifest.spec), "up", "-d")
    # An unhealthy facility must not become "current": write_provenance is what
    # `nuk status`, `nuk rollback` and drift.sh read as the deployed state, so
    # appending here would both hide the breakage and put the last known-good
    # entry out of rollback's reach (spec §5.4).
    if manifest.kind == "Facility" and (reason := facility_health(manifest)) is not None:
        die(f"{name}: facility is not healthy — {reason}. Provenance not appended.")
    # Provenance is best-effort: `status` prefers it over the live repo/ checkout
    # (trustworthy even for rsync-mirrored, .git-less workflow deploys), but a
    # write failure here must never fail an otherwise-successful apply.
    try:
        write_provenance(
            name,
            repo=source.repo,
            branch=source.branch,
            commit=_full_commit_sha(repo) if (repo / ".git").exists() else None,
            image_digest=_resolve_image_digest(name, manifest.spec),
        )
    except OSError as e:
        print(f"{name}: provenance not recorded ({e})")


def _migrate_colour(name: str, strategy: Strategy | None) -> str | None:
    """The idle colour a migration targets, or None for a colourless app.

    A blue-green deployment's compose services are colour-suffixed
    (`backend-blue`), and the migration must run the image the rollout is about
    to bring up — so, like the health probe (`strategy.health.service`), the
    service is suffixed with the idle colour and its compose profile enabled.
    """
    if strategy is not None and strategy.type == "blue-green":
        return idle_colour(active_colour(name))
    return None


def _migrate_service(name: str, migrate: Migrate, strategy: Strategy | None) -> str:
    """The compose service the migration runs in (colour-suffixed when blue-green)."""
    colour = _migrate_colour(name, strategy)
    return f"{migrate.service}-{colour}" if colour else migrate.service


def _run_migrations(
    name: str, spec: Spec, migrate: Migrate, strategy: Strategy | None, digest: str | None
) -> None:
    """Run the deployment's one-shot migration, failing the deploy on any error.

    The compose service supplies the image, env and network; nuk supplies the
    argv. A non-zero exit propagates as `CalledProcessError` (the apply pipeline
    records the manifest `failed`), a timeout becomes a fail-closed `SystemExit`.
    The digest is recorded only after success, so a crash mid-migration re-runs.
    """
    service = _migrate_service(name, migrate, strategy)
    colour = _migrate_colour(name, strategy)
    profile = ["--profile", colour] if colour else []
    argv = [
        *compose_args(name, spec),
        *profile,
        "run",
        "--rm",
        "--no-deps",
        service,
        *shlex.split(migrate.command),
    ]
    print(f"{name}: migrating ({service}: {migrate.command})")
    try:
        sh(*argv, timeout=migrate.timeout)
    except subprocess.TimeoutExpired:
        # SIGKILL reaches the compose client, not the container it started; stop
        # the one-off by hand so a hung migration cannot keep running against the DB.
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, spec), "rm", "-sf", service], check=False
        )
        die(f"{name}: migration timed out after {migrate.timeout}s — deploy aborted")
    except subprocess.CalledProcessError as e:
        die(f"{name}: migration failed (exit {e.returncode}): {migrate.command}")
    if digest:
        record_migrated_digest(name, digest)


def _apply_blue_green(  # noqa: PLR0913  # name/spec/ingress/vocab/strategy/dialect, one per concern
    name: str,
    spec: Spec,
    ingress: list[Ingress],
    vocab: dict[str, list[str]],
    strategy: Strategy,
    *,
    dialect: str = "edge",
) -> None:
    """Roll a blue-green deployment onto the idle colour.

    Brings the idle colour's compose profile up, gates on the strategy's health
    probe, flips the app-host file router to that colour, records it as active,
    and drains the previous colour — unless `keepPrevious` keeps it for an
    instant rollback.

    Args:
        name: The deployment name.
        spec: The manifest `spec` (for `compose_args`).
        ingress: The `spec.ingress[]` routes.
        vocab: Route capabilities resolved from the tree.
        strategy: The parsed `spec.strategy` block.
        dialect: The file-router dialect the flip writes; `"mesh"` on a router-mode
            app host, `"edge"` otherwise (see `build_ingress`).
    """
    active = active_colour(name)
    idle = idle_colour(active)
    health = strategy.health
    sh(*compose_args(name, spec), "--profile", idle, "up", "-d")
    # Resolve `sh` at call time (await_healthy's default binds the original at
    # import), so the probe runs through the same runner this host is configured
    # to use — and tests can capture it.
    await_healthy(
        _container_name(name, health.service, idle),
        health.path,
        timeout=health.timeout,
        interval=health.interval,
        port=health.port or 8000,
        exec_=sh,
    )
    write_ingress(name, ingress, vocab, colour=idle, dialect=dialect)
    record_active_colour(name, idle)
    record_router_dialect(name, dialect)
    if not strategy.keep_previous:
        # Drain every service the deployment publishes — the probe service plus
        # each ingress backend — so a manifest that names them other than the
        # conventional backend/frontend still tears the old colour fully down.
        # dict.fromkeys dedups while preserving manifest order.
        published = dict.fromkeys([health.service, *(i.service for i in ingress if i.service)])
        sh(
            *compose_args(name, spec),
            "--profile",
            active,
            "down",
            *(f"{service}-{active}" for service in published),
        )


def _rollback_blue_green(
    name: str,
    spec: Spec,
    ingress: list[Ingress],
    vocab: dict[str, list[str]],
    strategy: Strategy,
) -> None:
    """Flip a blue-green deployment's router back to its previous colour.

    The inverse of `_apply_blue_green`: the previous colour is the idle one, so
    bring its compose profile back up (a no-op when `keepPrevious` kept it, and
    the restart when the last apply drained it), gate on the same health probe,
    flip the app-host file router back to it, and record it as active. No image
    change is needed — the previous colour's bits are still on the host.

    `--no-recreate` is what makes that true. The previous colour is brought up
    against the CURRENT tree, and when both colours share one image ref (a bumped
    env value) a plain `up -d` would recreate the kept container on the NEW image,
    so the "rollback" would serve the bad release. With it, a kept container
    (`keepPrevious`) runs exactly the image it had. A drained colour (no
    `keepPrevious`) has no container left to preserve: it is created from the
    current tree, so only `keepPrevious: true` makes the flip a real rollback.
    """
    previous = idle_colour(active_colour(name))
    health = strategy.health
    sh(*compose_args(name, spec), "--profile", previous, "up", "-d", "--no-recreate")
    await_healthy(
        _container_name(name, health.service, previous),
        health.path,
        timeout=health.timeout,
        interval=health.interval,
        port=health.port or 8000,
        exec_=sh,
    )
    write_ingress(name, ingress, vocab, colour=previous, dialect=router_dialect(name))
    record_active_colour(name, previous)


def _compose_ps(name: str, fmt: str) -> list[str]:
    """`docker compose ps` lines for an app's project, one per container."""
    return (
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["docker", "compose", "-p", name, "ps", "--format", fmt],  # noqa: S607  # docker on PATH
            capture_output=True,
            text=True,
            check=False,
        )
        .stdout.strip()
        .splitlines()
    )


def cmd_get() -> None:
    """List deployments with their container state and ingress hosts."""
    for name in _known_deployments():
        manifest = load(_manifest_file(name))
        hosts = ",".join(i.host for i in manifest.spec.ingress)
        ps = ",".join(_compose_ps(name, "{{.State}}")) or "-"
        print(f"{name:24} {ps:32} {hosts}")


def _configured_service_image(
    name: str, spec: Spec, service: str, colour: str | None
) -> str | None:
    """The image reference compose CONFIGURES for `service`, or None if unresolvable.

    Resolved per service, with the colour's profile enabled: a blue-green
    deployment's services sit behind colour profiles, so a profile-less
    `config --images` lists only the profile-less ones (and in no stable order).
    """
    profile = ["--profile", colour] if colour else []
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, spec), *profile, "config", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        services = json.loads(proc.stdout).get("services") or {}
    except (subprocess.SubprocessError, OSError, ValueError, AttributeError):
        return None
    entry = services.get(service)
    image = entry.get("image") if isinstance(entry, dict) else None
    return image or None


def _configured_image_digest(
    name: str, spec: Spec, service: str, colour: str | None = None
) -> str | None:
    """Digest of the image the compose file CONFIGURES for `service`, or None.

    `docker compose images` reports the RUNNING containers — the previous release
    before a rollout — so it cannot answer "is this a new rollout"; the configured
    reference is the new tree's. A digest-pinned reference (`repo@sha256:...`) is
    its own identity and needs no daemon lookup (or local image); a tag resolves
    through the daemon's RepoDigests.
    """
    image = _configured_service_image(name, spec, service, colour)
    if image is None:
        return None
    if "@sha256:" in image:
        return image
    try:
        digest = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", image],  # noqa: S607  # docker on PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return digest or None


def _rollout_key(name: str, spec: Spec, migrate: Migrate, strategy: Strategy | None) -> str | None:
    """The key a rollout is compared by: the migrate service's image digest, else the revision.

    The converge loop re-applies every cycle, so `spec.migrate` must key off what
    actually changes on a new rollout — the image of the very service the
    migration runs in (`_migrate_service`), resolved under the idle colour's
    profile like the migration itself. `None` means neither resolved: the caller
    re-runs the (idempotent) migration rather than recording a sentinel that would
    collide across releases.
    """
    service = _migrate_service(name, migrate, strategy)
    digest = _configured_image_digest(name, spec, service, _migrate_colour(name, strategy))
    if digest:
        return digest
    revision = _applied_revision(name)
    return None if revision == "-" else revision


def _applied_revision(name: str) -> str:
    """Return the short git revision of an app's checkout, or `-` if unknown.

    Workflow-managed deploys mirror their tree with rsync (no `.git`), so they
    have no local revision to report; `-` is returned rather than shelling out.
    """
    repo = _repo_dir(name)
    if not (repo / ".git").exists():
        return "-"
    return _git_try(repo, "rev-parse", "--short", "HEAD") or "-"


def cmd_status(name: str) -> None:
    """Show one deployment's health, ingress, databases, and source provenance.

    Surfaces, for a single app: container/service state (`docker compose ps`),
    each ingress host with its upstream router health, the provisioned
    postgres/redis with **password-redacted** connection URLs (read back from the
    600 creds file via `read_db_env`, never the raw secret), and the source
    repo/branch plus the last applied git revision.
    """
    manifest_file = _manifest_file(name)
    if not manifest_file.exists():
        die(f"nuk: {name}: no such deployment ({manifest_file} not found)")
    manifest = load(manifest_file)
    source = manifest.spec.source

    ps = _compose_ps(name, "{{.Service}}: {{.State}}")
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


def cmd_status_overview(
    *, pretty: bool, show_all: bool, org_file: Path | None, probe: bool
) -> None:
    """Print the org-wide status Overview as JSON (walks DEPLOYS/*/; see build_overview).

    Args:
        pretty: Indent the JSON for human scanning; compact (single-line) otherwise.
        show_all: Also emit the `--all` soll-vs-ist block (needs `org_file`).
        org_file: Path to `nuklaut.org.yml`, required when `show_all` is set.
        probe: Best-effort outbound HTTPS probe per ingress host (off by default).
    """
    overview = build_overview(probe_enabled=probe)
    converge = read_converge_status()
    if converge is not None:
        overview = replace(overview, converge=converge)
    if show_all:
        overview = _soll_vs_ist(overview, org_file)
    print(json.dumps(overview.to_wire(), indent=2 if pretty else None))


def cmd_logs(name: str) -> None:
    """Follow compose logs for a deployment."""
    manifest = load(_manifest_file(name))
    sh(*compose_args(name, manifest.spec), "logs", "-f")


def cmd_rollout(name: str) -> None:
    """Git pull + compose pull + up -d for a deployment."""
    manifest = load(_manifest_file(name))
    repo = _repo_dir(name)
    if (repo / ".git").exists():
        sh("git", "-C", str(repo), "pull", "--ff-only")
    # else: workflow-managed deployment — re-trigger the workflow to update the tree.
    sh(*compose_args(name, manifest.spec), "pull")
    sh(*compose_args(name, manifest.spec), "up", "-d")


def _pin_image(name: str, spec: Spec, pin_digest: str) -> None:
    """Point the app's compose image reference at the pinned digest (spec §8).

    The digest is the identity of the re-applied release. Order matters:
    resolve the retag targets from the (already detached) compose tree first,
    then `docker pull` the digest — the pull IS the preflight, and its failure
    aborts before anything is written or recreated, leaving the current state
    running. The runner's pre-pull model (cmd_apply's "No --pull here") already treats the
    daemon's tags as shared mutable state; this is the same move in the
    opposite direction.

    Raises:
        NukError: If no compose image comes from the digest's repository, or
            the pull fails.
    """
    repo_name = pin_digest.split("@", maxsplit=1)[0]
    refs = [
        ref for ref in _compose_images(name, spec) if ref.split("@")[0].split(":")[0] == repo_name
    ]
    if not refs:
        die(
            f"{name}: the pinned compose references no image from {repo_name} — "
            f"cannot pin {pin_digest}"
        )
    sh("docker", "pull", pin_digest)
    for ref in refs:
        sh("docker", "tag", pin_digest, ref)


def cmd_rollback(name: str, to: int | None, show: bool) -> None:  # noqa: C901  # each branch is a distinct fail-closed refusal (spec §8)
    """Re-apply a previously recorded release of `name` (spec §8).

    Rollback is a HUMAN act. The loop never rolls back on its own: apply is
    idempotent and the previous stack keeps running, so an auto-rollback would
    fight a human mid-incident (spec §7.5).

    The selected entry is APPENDED as the new head (Helm-revision semantics,
    never a pointer rewind): `cmd_apply` runs the ordinary pipeline, and its
    provenance write records the release being re-applied with a fresh
    timestamp.

    A blue-green Deployment rolls back differently. `nuk rollback <name>` with
    no `to` performs a COLOUR FLIP, not a digest re-apply: the router flips back
    to the previous (idle) colour — brought up and health-gated first — and that
    colour is recorded active (the inverse of `_apply_blue_green`); there is
    nothing to pull or pin because the previous colour's bits are already on the
    host. `to` is NOT honoured on the flip — it only selects a release for the
    digest path — so a blue-green rollback with an explicit index falls through
    to the ordinary digest re-apply of release `to`. The flip refuses when no
    colour has been recorded (there is no previous colour to flip to).

    Args:
        name: The deployment name.
        to: History index to restore; None means the entry before the current
            one (or, for a blue-green Deployment, the colour flip). Negative
            indices count from the end, so `-1` is the current release (a
            re-apply) and `-2` is the previous one.
        show: Print the history and apply nothing.

    Raises:
        NukError: If there is nothing to roll back to, the index is out of
            range, the target entry lacks its imageDigest or its commit, the
            persisted manifest is gone, it no longer validates under the
            current schema, or it is a Facility (facility rollback is the tag,
            §8).
    """
    history = read_provenance_history(name)
    if show:
        if not history:
            print(f"{name}: no releases recorded")
            return
        for i, entry in enumerate(history):
            commit = (entry.commit or "-")[:12]
            digest = (entry.image_digest or "-").split("@")[-1][:12]
            marker = "  (current)" if i == len(history) - 1 else ""
            print(f"{i:>3}  {commit}  {digest}  {entry.applied_at or '?'}{marker}")
        return
    manifest = _manifest_file(name)
    if not manifest.exists():
        die(f"{name}: {manifest} is missing — nothing to re-apply")
    try:
        raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        parsed = models._MANIFEST_ADAPTER.validate_python(raw)
    except ValidationError as e:
        die(
            f"{name}: the persisted manifest no longer validates under the current "
            f"schema (a field was removed since; spec §8) — refusing to silently "
            f"upgrade it into the new schema: {e}"
        )
    if parsed.kind != "Deployment":
        die(
            f"{name}: the persisted manifest is a {parsed.kind}, not a Deployment — "
            f"facility rollback needs no mechanism, cut a new tag at the old tree (spec §8)"
        )
    strategy = parsed.spec.strategy if parsed.spec is not None else None
    if to is None and strategy is not None and strategy.type == "blue-green":
        # A blue-green rollback is a colour flip, not a digest re-apply: the
        # previous colour's bits are already on the host (keepPrevious kept it),
        # so there is nothing to pull or pin. The router flips back to it and it
        # is recorded active — the inverse of `_apply_blue_green`. `to` is not
        # honoured here: an explicit index selects a release to re-apply by
        # digest (below), so it skips this flip and takes the ordinary path.
        if not _active_colour_file(name).exists():
            # `active_colour` would default to blue, flipping to a colour that
            # never ran. Refuse instead, mirroring the digest path's wording.
            die(f"{name}: no previous release recorded — nothing to roll back to")
        # Resolve the vocabulary the same way `cmd_apply` does, from the
        # manifest's tree, so rollback and apply cannot drift. The persisted
        # manifest lives in the deploy state dir, which ships no facilities/, so
        # this falls back to DEFAULT_ROUTE_VOCAB — the built-in chain that
        # duplicates infra/facilities/basic.yml's `basic -> [auth@file]`, kept in
        # step by test_shipped_facilities_reproduce_the_default_vocabulary. A
        # deployment using a tree-only capability would re-render without it
        # until the next converge cycle corrects it.
        ctx = TreeContext.for_path(manifest)
        vocab = route_vocabulary(ctx.facilities) if ctx.facilities else DEFAULT_ROUTE_VOCAB
        _rollback_blue_green(name, parsed.spec, parsed.spec.ingress, vocab, strategy)
        return
    if to is None and len(history) < 2:  # noqa: PLR2004  # need a current AND a previous
        die(f"{name}: no previous release recorded — nothing to roll back to")
    index = -2 if to is None else to
    try:
        entry = history[index]
    except IndexError:
        die(f"{name}: no release at index {to} (history has {len(history)} entries)")
    digest = entry.image_digest
    if not digest:
        die(
            f"{name}: the release at index {index} has no recorded imageDigest "
            f"(a source-built deploy, or one predating digest resolution) — it cannot "
            f"be re-applied by digest (spec §8). Roll forward, or re-apply its commit by hand."
        )
    commit = entry.commit
    if not commit:
        die(
            f"{name}: the release at index {index} has no recorded commit "
            f"(a workflow deploy from a .git-less tree) — its compose tree is "
            f"unreproducible, cannot re-apply it"
        )
    print(f"{name}: rolling back to {digest} (applied {entry.applied_at or '?'})")
    cmd_apply(manifest, None, pin_commit=commit, pin_digest=digest)


def cmd_delete(name: str, purge: bool) -> None:
    """Tear down a deployment, keeping its database unless `purge` is set."""
    pdir = project_dir(name)
    if (pdir / "manifest.yml").exists():
        manifest = load(pdir / "manifest.yml")
        subprocess.run([*compose_args(name, manifest.spec), "down", "-v"], check=False)  # noqa: S603  # argv built from fixed verbs
    _router_file(name).unlink(missing_ok=True)
    shutil.rmtree(pdir, ignore_errors=True)
    # The app's database is kept by default — its creds file (in SECRETS, not
    # pdir) survives rmtree and keeps nuk aware of it (see `nuk db ls`). --purge
    # is the only path that destroys data.
    if purge:
        purge_databases(name)
    elif _db_env_path(name).exists():
        print(f"{name}: database retained. `nuk db ls` to view, `nuk db purge {name}` to drop it.")


def cmd_db_ls() -> None:
    """List managed databases; flag retained ones with no live deployment."""
    for app in _db_env_apps():
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
        live = (_manifest_file(app)).exists()
        status = "deployed" if live else "RETAINED (no deployment — nuk db purge to drop)"
        print(f"{app:24} {kinds:16} {status}")


def cmd_db_purge(name: str) -> None:
    """Drop a retained app's database + creds."""
    purge_databases(name)
    print(f"{name}: database purged.")


# --- shell completion ---------------------------------------------------------


def _known_deployments() -> list[str]:
    """List deployment names (dirs holding a persisted manifest); `cmd_get` iterates these.

    Returns empty (never raises) off the controller, where DEPLOYS is absent, so
    shell completion degrades gracefully.
    """
    if not paths.DEPLOYS.exists():
        return []
    return sorted(
        p.name for p in paths.DEPLOYS.iterdir() if p.is_dir() and (p / "manifest.yml").exists()
    )


def complete_deployment_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for deployment-name arguments (logs/rollout/...)."""
    return [n for n in _known_deployments() if n.startswith(incomplete)]


def complete_db_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for `db purge` — retained DB creds in SECRETS.

    Purge targets a database by its creds file, which outlives the deployment
    (see `cmd_db_ls`), so this enumerates SECRETS rather than live deployments.
    """
    return [n for n in _db_env_apps() if n.startswith(incomplete)]


# --- typer CLI ----------------------------------------------------------------

_EPILOG = """\
Manifest (apiVersion: nuk/v1, kind: Deployment):
  metadata.name, spec.source.{repo,branch}, spec.compose.file,
  spec.ingress[].{host,service,port}, spec.envFrom[].secretRef
  spec.ingress[] also takes optional: path (PathPrefix), stripPrefix,
    priority, www (301 www.<host> -> <host>; apex domains only),
    auth ("basic" -> HTTP Basic Auth; refused unless a Facility provides the capability)
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
        NukError: When `/opt/nuklaut` is absent (nuk runs on the controller).
            The `org` and `update` subcommands are exempt — they run off the
            controller too (operator workstation, CI, the deploy plugin).
    """
    if ctx.invoked_subcommand in {"org", "update"}:
        return
    if not paths.ROOT.exists():
        die(
            f"nuk: {paths.ROOT} does not exist — nuk runs on the controller, "
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
        str | None,
        typer.Argument(
            help="deployment name; omit for the org-wide overview",
            autocompletion=complete_deployment_name,
        ),
    ] = None,
    pretty: Annotated[
        bool,
        typer.Option("--json", help="pretty-print the org-wide overview (always JSON either way)"),
    ] = False,
    show_all: Annotated[
        bool,
        typer.Option(
            "--all",
            help="org-wide: also compare against the declared org manifest (needs --org-file)",
        ),
    ] = False,
    org_file: Annotated[
        Path | None,
        typer.Option("--org-file", help="path to nuklaut.org.yml (required with --all)"),
    ] = None,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe",
            help="org-wide: best-effort outbound HTTPS probe per ingress host (off by default)",
        ),
    ] = False,
) -> None:
    """Show one app's health/ingress/databases/source (NAME), or the org-wide overview as JSON."""
    if name is not None:
        cmd_status(name)
        return
    cmd_status_overview(pretty=pretty, show_all=show_all, org_file=org_file, probe=probe)


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


@app.command("rollback")
def _rollback(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=complete_deployment_name)
    ],
    to: Annotated[
        int | None,
        typer.Option("--to", help="history index to restore (default: the previous release)"),
    ] = None,
    show: Annotated[
        bool, typer.Option("--list", help="print the release history and apply nothing")
    ] = False,
) -> None:
    """Re-apply a previously recorded release."""
    cmd_rollback(name, to, show)


@app.command("converge")
def _converge(
    sources: Annotated[
        Path, typer.Option("--sources", help="sources.yml: repos, deploy keys, what each applies")
    ] = paths.SOURCES_FILE,
    signers_dir: Annotated[
        Path, typer.Option("--signers-dir", help="allowed_signers.d: one trust file per source")
    ] = paths.SIGNERS_DIR,
    state_dir: Annotated[
        Path, typer.Option("--state-dir", help="lock, per-source state, status file")
    ] = paths.CONVERGE_STATE,
) -> None:
    """Converge this host from every source to its newest verifying tag (spec §7)."""
    raise typer.Exit(
        cmd_converge(sources_file=sources, signers_dir=signers_dir, state_dir=state_dir)
    )


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
    name: Annotated[str, typer.Argument(help="deployment name", autocompletion=complete_db_name)],
) -> None:
    """Drop a retained app's database + creds."""
    cmd_db_purge(name)


def _uv_bin_dir() -> str | None:
    """The directory the running `nuk` shim lives in, or None if unresolvable.

    `uv tool install` writes its entry point into `UV_TOOL_BIN_DIR` (default
    `~/.local/bin`), which on a fleet host is not on PATH while the converge unit
    runs `/usr/local/bin/nuk converge` — so a bare `nuk update` moves the shim and
    breaks the timer. Pinning the install to the shim's own directory keeps the
    command that invoked us working.
    """
    exe = shutil.which("nuk") or sys.argv[0]
    if not exe:
        return None
    path = Path(exe)
    # Deliberately not `.resolve()`: the shim is a symlink INTO the tool venv, and
    # it is the shim's own directory (e.g. `/usr/local/bin`) that must receive the
    # new one.
    return str((path if path.is_absolute() else Path.cwd() / path).parent)


def cmd_update(to: str | None, check: bool) -> None:
    """Install the latest nuk release (or an explicit ref) via `uv tool install`.

    Args:
        to: Explicit ref/tag to install (bypasses the up-to-date check, so it also
            supports pinning/downgrade); None installs the latest release.
        check: Only report installed-vs-latest; install nothing.

    Raises:
        NukError: If the latest release cannot be resolved, or the uv install fails.
    """
    current = __version__
    target = to or latest_release_tag()
    if not target:
        die("nuk update: could not resolve the latest release (network?). Pass --to <ref>.")
    if check:
        print(f"nuk {current} installed - latest is {target}")
        return
    if to is None and norm_ver(target) and norm_ver(target) <= norm_ver(current):
        print(f"nuk {current} is already up to date ({target})")
        return
    print(f"updating nuk {current} -> {target} via uv tool install...")
    bin_dir = _uv_bin_dir()
    env = {**os.environ, "UV_TOOL_BIN_DIR": bin_dir} if bin_dir else None
    try:
        sh("uv", "tool", "install", "--force", "--from", f"{NUK_GIT}@{target}", "nuk", env=env)
    except (subprocess.SubprocessError, OSError) as e:
        hint = f"UV_TOOL_BIN_DIR={bin_dir} " if bin_dir else ""
        die(
            f"nuk update: uv install failed ({e}). Is uv installed? "
            f"Manual: {hint}uv tool install --from {NUK_GIT}@{target} nuk"
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
        die("nuk org resolve: no github origin remote found")
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
    key: Annotated[str, typer.Argument(help="dotted key, e.g. facilities.dnsProvider")],
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
