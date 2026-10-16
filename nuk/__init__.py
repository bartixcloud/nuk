#!/usr/bin/env python3
"""nuk — minimal Kubernetes-shaped Docker Compose deployer.

Manifests (apiVersion: nuk/v1, kind: Deployment | Facility) describe one compose
project each: its source, ingress, env files, databases, and placement. Deploy
state lives in /opt/nuklaut/, the convergence loop's state and release history in
/var/lib/nuk/, host identity and trust anchors in /etc/nuklaut/. No daemon.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Self, cast

import yaml

from nuk import compose as compose
from nuk import converge as converge
from nuk import databases as databases
from nuk import facility as facility
from nuk import ingress as ingress
from nuk import models as models
from nuk import org as org
from nuk import paths
from nuk import provenance as provenance
from nuk import rollout as rollout
from nuk import sources as sources
from nuk import status as status
from nuk.cli import (
    _apply as _apply,
)
from nuk.cli import (
    _converge as _converge,
)
from nuk.cli import (
    _db_ls as _db_ls,
)
from nuk.cli import (
    _db_purge as _db_purge,
)
from nuk.cli import (
    _delete as _delete,
)
from nuk.cli import (
    _emit as _emit,
)
from nuk.cli import (
    _list as _list,
)
from nuk.cli import (
    _logs as _logs,
)
from nuk.cli import (
    _org_get as _org_get,
)
from nuk.cli import (
    _org_resolve as _org_resolve,
)
from nuk.cli import (
    _org_show as _org_show,
)
from nuk.cli import (
    _org_validate as _org_validate,
)
from nuk.cli import (
    _rollback as _rollback,
)
from nuk.cli import (
    _rollout as _rollout,
)
from nuk.cli import (
    _root as _root,
)
from nuk.cli import (
    _status as _status,
)
from nuk.cli import (
    _update as _update,
)
from nuk.cli import (
    _uv_bin_dir as _uv_bin_dir,
)
from nuk.cli import (
    _version as _version,
)
from nuk.cli import (
    app as app,
)
from nuk.cli import (
    cmd_update as cmd_update,
)
from nuk.cli import (
    main as main,
)
from nuk.compose import (
    _compose_images as _compose_images,
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
    _resolve_image_digest as _resolve_image_digest,
)
from nuk.compose import (
    compose_args as compose_args,
)
from nuk.compose import (
    compose_service_names as compose_service_names,
)
from nuk.compose import (
    resolve_db_services as resolve_db_services,
)
from nuk.compose import (
    resolve_env_from as resolve_env_from,
)
from nuk.compose import (
    write_override as write_override,
)
from nuk.converge import (
    _apply_source as _apply_source,
)
from nuk.converge import (
    _cached_delegations as _cached_delegations,
)
from nuk.converge import (
    _converge_source as _converge_source,
)
from nuk.converge import (
    _declared_names as _declared_names,
)
from nuk.converge import (
    _deployment_tree as _deployment_tree,
)
from nuk.converge import (
    _exit_reason as _exit_reason,
)
from nuk.converge import (
    _host_auth as _host_auth,
)
from nuk.converge import (
    _load_prepared_delegations as _load_prepared_delegations,
)
from nuk.converge import (
    _logging_status as _logging_status,
)
from nuk.converge import (
    _prepare_source as _prepare_source,
)
from nuk.converge import (
    _provided_capabilities as _provided_capabilities,
)
from nuk.converge import (
    _refuse as _refuse,
)
from nuk.converge import (
    _refuse_bad_declarations as _refuse_bad_declarations,
)
from nuk.converge import (
    _render_routers as _render_routers,
)
from nuk.converge import (
    _run_cycle as _run_cycle,
)
from nuk.converge import (
    _UnknownAuthorizationError as _UnknownAuthorizationError,
)
from nuk.converge import (
    apply_tree as apply_tree,
)
from nuk.converge import (
    archive_tree as archive_tree,
)
from nuk.converge import (
    cmd_converge as cmd_converge,
)
from nuk.converge import (
    consumes as consumes,
)
from nuk.converge import (
    converge_lock as converge_lock,
)
from nuk.converge import (
    placement_matches as placement_matches,
)
from nuk.converge import (
    provision_remote_databases as provision_remote_databases,
)
from nuk.converge import (
    read_converge_status as read_converge_status,
)
from nuk.converge import (
    reap_report as reap_report,
)
from nuk.converge import (
    render_routes as render_routes,
)
from nuk.converge import (
    write_converge_status as write_converge_status,
)
from nuk.databases import (
    _container_state as _container_state,
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
    _redact_db_url as _redact_db_url,
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
    data_host_ip as data_host_ip,
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
    provision_databases as provision_databases,
)
from nuk.databases import (
    purge_databases as purge_databases,
)
from nuk.databases import (
    read_db_env as read_db_env,
)
from nuk.databases import (
    write_db_env as write_db_env,
)
from nuk.facility import (
    APPLY_ALL as APPLY_ALL,
)
from nuk.facility import (
    DEPLOYMENT_DIR as DEPLOYMENT_DIR,
)
from nuk.facility import (
    FACILITY_DIR as FACILITY_DIR,
)
from nuk.facility import (
    ROUTER_PORT as ROUTER_PORT,
)
from nuk.facility import (
    TreeContext as TreeContext,
)
from nuk.facility import (
    _router_present as _router_present,
)
from nuk.facility import (
    _tree_root as _tree_root,
)
from nuk.facility import (
    env_facility as env_facility,
)
from nuk.facility import (
    facility_health as facility_health,
)
from nuk.facility import (
    load_deployments as load_deployments,
)
from nuk.facility import (
    load_facilities as load_facilities,
)
from nuk.facility import (
    route_vocabulary as route_vocabulary,
)
from nuk.ingress import (
    RouteResult as RouteResult,
)
from nuk.ingress import (
    _authorized_ingress as _authorized_ingress,
)
from nuk.ingress import (
    _refuse_route as _refuse_route,
)
from nuk.ingress import (
    _rule,
)
from nuk.ingress import (
    backend_address as backend_address,
)
from nuk.ingress import (
    build_override as build_override,
)
from nuk.ingress import (
    reap_legacy_worker_routers as reap_legacy_worker_routers,
)
from nuk.ingress import (
    render_edge_routers as render_edge_routers,
)
from nuk.ingress import (
    write_ingress as write_ingress,
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
    Deployment as Deployment,
)
from nuk.models import (
    EnvFrom as EnvFrom,
)
from nuk.models import (
    EnvProvide as EnvProvide,
)
from nuk.models import (
    Facility as Facility,
)
from nuk.models import (
    FacilitySpec as FacilitySpec,
)
from nuk.models import (
    Health as Health,
)
from nuk.models import (
    Ingress,  # noqa: TC001
    Spec,  # noqa: TC001
)
from nuk.models import (
    Metadata as Metadata,
)
from nuk.models import (
    Migrate as Migrate,
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
    Strategy as Strategy,
)
from nuk.models import (
    StrategyHealth as StrategyHealth,
)
from nuk.models import (
    ValidationError as ValidationError,  # noqa: TC001
)
from nuk.models import (
    _NullTolerant as _NullTolerant,
)
from nuk.models import (
    load as load,
)
from nuk.org import (
    _ENTRY_ROLES as _ENTRY_ROLES,
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
    Delegation,
    Host,
    Org,
    TenantRegistry,
    resolve_host_owner,
)
from nuk.org import (
    Delegations as Delegations,
)
from nuk.org import (
    Facilities as Facilities,
)
from nuk.org import (
    check_cross_zone_patterns as check_cross_zone_patterns,
)
from nuk.org import (
    host_in_domains as host_in_domains,
)
from nuk.org import (
    load_cached_delegations as load_cached_delegations,
)
from nuk.org import (
    load_delegations as load_delegations,
)
from nuk.org import (
    load_org as load_org,
)
from nuk.org import (
    load_tenants as load_tenants,
)
from nuk.org import (
    resolve_manifest as resolve_manifest,
)
from nuk.org import (
    specificity as specificity,
)
from nuk.org import (
    store_delegations as store_delegations,
)
from nuk.org import (
    validate_delegations as validate_delegations,
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
    latest_release_tag as latest_release_tag,
)
from nuk.provenance import (
    read_provenance as read_provenance,
)
from nuk.provenance import (
    read_provenance_history as read_provenance_history,
)
from nuk.provenance import (
    write_provenance as write_provenance,
)
from nuk.records import ConvergeStatus  # noqa: TC001
from nuk.records import (
    LoggingStatus as LoggingStatus,
)
from nuk.records import (
    ManifestKind as ManifestKind,
)
from nuk.records import (
    ManifestOutcome as ManifestOutcome,
)
from nuk.records import (
    ManifestResult as ManifestResult,
)
from nuk.records import (
    SourceBlock as SourceBlock,
)
from nuk.rollout import (
    _FACILITY_GROUP as _FACILITY_GROUP,
)
from nuk.rollout import (
    _applied_revision as _applied_revision,
)
from nuk.rollout import (
    _apply_blue_green as _apply_blue_green,
)
from nuk.rollout import (
    _compose_ps as _compose_ps,
)
from nuk.rollout import (
    _configured_image_digest as _configured_image_digest,
)
from nuk.rollout import (
    _configured_service_image as _configured_service_image,
)
from nuk.rollout import (
    _is_privileged as _is_privileged,
)
from nuk.rollout import (
    _migrate_colour as _migrate_colour,
)
from nuk.rollout import (
    _migrate_service as _migrate_service,
)
from nuk.rollout import (
    _pin_image as _pin_image,
)
from nuk.rollout import (
    _repo_identity as _repo_identity,
)
from nuk.rollout import (
    _rollback_blue_green as _rollback_blue_green,
)
from nuk.rollout import (
    _rollout_key as _rollout_key,
)
from nuk.rollout import (
    _run_migrations as _run_migrations,
)
from nuk.rollout import (
    _same_repo as _same_repo,
)
from nuk.rollout import (
    cmd_apply as cmd_apply,
)
from nuk.rollout import (
    cmd_db_ls as cmd_db_ls,
)
from nuk.rollout import (
    cmd_db_purge as cmd_db_purge,
)
from nuk.rollout import (
    cmd_delete as cmd_delete,
)
from nuk.rollout import (
    cmd_get as cmd_get,
)
from nuk.rollout import (
    cmd_logs as cmd_logs,
)
from nuk.rollout import (
    cmd_rollback as cmd_rollback,
)
from nuk.rollout import (
    cmd_rollout as cmd_rollout,
)
from nuk.rollout import (
    cmd_status as cmd_status,
)
from nuk.rollout import (
    cmd_status_overview as cmd_status_overview,
)
from nuk.sources import (
    SOURCE_BRANCH as SOURCE_BRANCH,
)
from nuk.sources import (
    SourceEntry as SourceEntry,
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
    load_sources as load_sources,
)
from nuk.sources import (
    record_applied as record_applied,
)
from nuk.sources import (
    resolve_signed_tag as resolve_signed_tag,
)
from nuk.sources import (
    source_state_dir as source_state_dir,
)
from nuk.sources import (
    sync_source as sync_source,
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
    _soll_vs_ist as _soll_vs_ist,
)
from nuk.status import (
    build_overview as build_overview,
)
from nuk.util import (
    NukError as NukError,
)
from nuk.util import (
    _atomic_write as _atomic_write,
)
from nuk.util import (
    _chown_deploy as _chown_deploy,
)
from nuk.util import (
    _full_commit_sha as _full_commit_sha,
)
from nuk.util import (
    _git as _git,
)
from nuk.util import (
    _git_try as _git_try,
)
from nuk.util import (
    _int_or_none,
    _read_env_file,
    _str_or_none,
    die,
    git_origin,
    sh,
)
from nuk.util import (
    _is_ancestor as _is_ancestor,
)
from nuk.util import (
    _iso_utc_now as _iso_utc_now,
)
from nuk.util import (
    _read_json_safe as _read_json_safe,
)
from nuk.util import (
    _read_yaml_safe as _read_yaml_safe,
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
from nuk.util import (
    norm_ver as norm_ver,
)
from nuk.util import (
    origin_org as origin_org,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from nuk.records import (
        Json,
    )

__version__ = "2.7.0"  # bumped on release by .github/workflows/release.yml

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
