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
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal, cast
from urllib.parse import urlparse

import typer
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    TypeAdapter,
    ValidationError,
    model_validator,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

__version__ = "2.0.0"  # bumped on release by .github/workflows/release.yml

ROOT = Path("/opt/nuklaut")
DEPLOYS = ROOT / "deployments"
DYNAMIC = ROOT / "traefik" / "dynamic"
SECRETS = ROOT / "secrets"
# This host's identity, written world-readable (no secrets) by cloud-init. Absent on a
# legacy single-host controller -> read_self() defaults to an entry role (byte-identical).
HOST_ENV = Path("/etc/nuklaut/host.env")
# The convergence loop's state (spec §7). /var/lib per the FHS: machine-local,
# persistent, not configuration. Held apart from /opt/nuklaut so that wiping a
# host's deployments does not also erase the downgrade guard's memory.
CONVERGE_STATE = Path("/var/lib/nuk")
# Which repos this host converges from, each with its read-only deploy key and what it
# may change here (contracts C3). Delivered by seed.sh, never by the repos it lists.
SOURCES_FILE = Path("/etc/nuklaut/sources.yml")
# One signers file per source, named after it: a tenant's key can verify that tenant's
# tags and nobody else's (contracts C3). Plain `git verify-tag`, no principal flag.
SIGNERS_DIR = Path("/etc/nuklaut/allowed_signers.d")
# github.com's host key, pinned by cloud-init; the deploy-key fetch never trusts on first use.
KNOWN_HOSTS = Path("/etc/nuklaut/known_hosts")
# Only the CLI default: cmd_converge derives both files from its state_dir argument,
# so the tests get a tmp_path and the host gets /var/lib/nuk.
CONVERGE_STATUS = CONVERGE_STATE / "converge-status.json"
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

# The fleet DB seed: delivered by converge.sh via the existing sops channel to
# the data + app hosts only. Both hosts derive per-app passwords from it, so no
# credential is ever transported (spec §3.1).
DB_SEED_ENV = Path("/etc/nuklaut/secrets/db-seed.env")

# The capability name a Deployment's `spec.databases` block asks for; the
# data-stack facility declares it via spec.provides.env.capability.
_DATABASES_CAPABILITY = "databases"

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
    # Opt into deploying the branch head without a signed `v*` tag — for
    # non-prod/test deployments. Prod deployments leave this False and require
    # a signed tag.
    unsigned: bool = False


class Compose(BaseModel):
    """`spec.compose` — path to the compose file inside the repo."""

    file: str = "docker-compose.yml"

    @model_validator(mode="before")
    @classmethod
    def _coerce_string(cls, data: object) -> object:
        """Allow passing compose as a string directly (converted to {file: ...})."""
        if isinstance(data, str):
            return {"file": data}
        return data


class Ingress(BaseModel):
    """One `spec.ingress[]` entry — a single Traefik router/service."""

    model_config = ConfigDict(populate_by_name=True)

    host: str
    service: str | None = None
    port: int | None = None
    # "<ip>:<port>" backend outside this host's docker "edge" network — e.g. a
    # libvirt VM on a separate hypervisor host, reached over the private
    # vswitch/cloud-network. Mutually exclusive with service/port.
    address: str | None = None
    path: str | None = None
    strip_prefix: bool = Field(default=False, alias="stripPrefix")
    priority: int | None = None
    www: bool = False
    # When this app runs on a non-edge host (worker), its container port is published on
    # the private IP for the edge Traefik to reach it. hostPort overrides the HOST side of
    # that bind (default = port), so two worker apps sharing a container port don't collide
    # on the host. Ignored on an edge/all-in-one host (no publish). Finding 6.
    host_port: int | None = Field(default=None, alias="hostPort")
    # Which gate to put in front of this route. Since authentik and oauth2-proxy were retired
    # `basic` is the only value, and it resolves through the route capability of the same name.
    # This MUST stay a closed set: an unknown value used to render a router with NO auth
    # middleware and NO error, an authentication control failing OPEN on a typo. A retired value
    # (`oauth`, `authentik`) is now a load-time ValidationError.
    auth: Literal["basic"] | None = None

    @model_validator(mode="after")
    def _check_backend(self) -> Ingress:
        """Exactly one backend: `address` (remote) or `service`+`port` (local).

        Raises:
            ValueError: If both or neither backend forms are given.
        """
        if self.address and (self.service is not None or self.port is not None):
            msg = "ingress: set either `address` or `service`+`port`, not both"
            raise ValueError(msg)
        if not self.address and (self.service is None or self.port is None):
            msg = "ingress: `service` and `port` are required unless `address` is set"
            raise ValueError(msg)
        return self


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


# The host roles a placement can target and an org host can carry (spec §3.1).
Role = Literal["edge", "data", "app", "hypervisor", "all-in-one"]


class Placement(BaseModel):
    """`spec.placement` — the role whose hosts run this manifest's containers.

    Shared by both kinds (spec §4.2). Replaces the two implicit placement
    mechanisms it supersedes: "whichever host someone ran `nuk apply` on", and
    converge.sh's retired APPS environment variable.
    """

    role: Role


class Health(_NullTolerant):
    """`spec.health` — how a facility proves it is actually up.

    Vocabulary is git-derived and fleet-wide; health is same-host (spec §5.3).
    Only the host whose `placement.role` owns a facility can check it.
    """

    containers: list[str] = []


class RouteProvide(BaseModel):
    """`spec.provides.route` — a stateless decoration a router can opt into.

    `capability` is what the facility HANDS OUT; a Deployment consumes it by
    naming it in a field (`ingress[].auth: basic` → capability `basic`).
    `middlewares` are applied in declaration order, outer→inner.
    """

    capability: str
    middlewares: list[str] = []


class EnvProvide(BaseModel):
    """`spec.provides.env` — a stateful binding handed to an app as env vars.

    `bind` names the wire protocol a capability is offered on. `postgres`
    is a SQL bind to a provisioned cluster; `otlp` is an OTLP ingest
    endpoint (facility `logging`, spec §14.1) — declared for the vocabulary
    only, since no manifest field consumes `logs` (§14.3) and no code
    branches on the value.
    """

    capability: str
    bind: Literal["postgres", "otlp"]


class Provides(_NullTolerant):
    """`spec.provides` — what a Facility hands out.

    The whole of `Facility ≡ Deployment + spec.provides`.
    """

    route: RouteProvide | None = None
    env: EnvProvide | None = None


class StrategyHealth(_NullTolerant):
    """`spec.strategy.health` — the blue-green readiness probe for one service.

    Distinct from the facility `Health` (`spec.health.containers`): this one
    names a compose service and the HTTP path that proves its idle colour is up.
    """

    model_config = ConfigDict(populate_by_name=True)

    service: str
    path: str
    port: int | None = None
    timeout: int = 120
    interval: float = 2.0


class Strategy(_NullTolerant):
    """`spec.strategy` — how a Deployment rolls out its containers.

    `blue-green` brings the idle colour up, gates on `health`, flips the
    app-host router to it, then drains the previous colour — unless
    `keepPrevious` keeps it running for an instant rollback.
    """

    model_config = ConfigDict(populate_by_name=True)

    type: Literal["blue-green"]
    health: StrategyHealth
    drain: int = 30
    keep_previous: bool = Field(default=True, alias="keepPrevious")


class Spec(_NullTolerant):
    """The manifest `spec` block."""

    model_config = ConfigDict(populate_by_name=True)

    source: Source = Source()
    compose: Compose = Compose()
    ingress: list[Ingress] = []
    env_from: list[EnvFrom] = Field(default=[], alias="envFrom")
    databases: Databases = Databases()
    placement: Placement | None = None
    strategy: Strategy | None = None


class Metadata(BaseModel):
    """The manifest `metadata` block."""

    name: str


class FacilitySpec(Spec):
    """A Facility's `spec` — a Deployment's spec plus what it hands out.

    `Facility ≡ Deployment + spec.provides` (spec §4.2). `source`, `compose`,
    `ingress`, `databases`, `placement` are inherited unchanged.
    """

    provides: Provides = Provides()
    health: Health = Health()


class Manifest(_NullTolerant):
    """The fields every nuk/v1 document shares, whatever its kind.

    Carries the typed view used by the command layer plus the raw parsed dict
    (`raw`) handed unchanged to the wire-contract render functions, so their
    YAML output never shifts shape.
    """

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nuk/v1"] = Field(alias="apiVersion")
    metadata: Metadata

    _raw: dict = PrivateAttr(default_factory=dict)

    @property
    def raw(self) -> dict:
        """The original parsed manifest dict (wire-contract input)."""
        return self._raw


class Deployment(Manifest):
    """An app stack: containers, ingress, optional databases."""

    kind: Literal["Deployment"]
    spec: Spec = Spec()


class Facility(Manifest):
    """A platform service that additionally declares what it provides."""

    kind: Literal["Facility"]
    spec: FacilitySpec = FacilitySpec()


# One document family, one apiVersion, one union — discriminated on `kind` so a
# typo in `kind` is a validation error rather than a silently-skipped document.
AnyManifest = Annotated[Deployment | Facility, Field(discriminator="kind")]
_MANIFEST_ADAPTER = TypeAdapter(AnyManifest)


# --- org capability manifest (nukorg/v1) --------------------------------------
# One org's declarative facility choices, read by BOTH the core bootstrap (to
# BUILD the platform) and the deploy plugin (to OPERATE it). Kept flat (not
# spec-nested like nuk/v1) because it is human-edited and read key-by-key by
# shell (`nuk org get facilities.dnsProvider`); dotted paths use the YAML alias names.


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
    runners: Literal["none", "ephemeral", "persistent"]
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
        if self.dns == "manual" and self.tls != "http01":
            # Manual DNS cannot answer the DNS-01 challenge automatically; the only
            # operated pairing for manual records is the HTTP-01 challenge.
            msg = "facilities.dns=manual requires facilities.tls=http01"
            raise ValueError(msg)
        return self


class Network(BaseModel):
    """`network` — the private-network plan (Hetzner Cloud-Network + vSwitch).

    Declared from the start but only wired up from the multi-host chapter on; a
    single-host org may omit it entirely (then no subnet checks run).
    """

    model_config = ConfigDict(populate_by_name=True)

    cidr: str
    cloud_subnet: str = Field(alias="cloudSubnet")
    vswitch_subnet: str = Field(alias="vswitchSubnet")
    vswitch_vlan: int = Field(alias="vswitchVlan")
    vswitch_name: str | None = Field(default=None, alias="vswitchName")


class Host(BaseModel):
    """`hosts[]` — one machine or VM the org runs, addressed by its private IP."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    provider: Literal["hcloud", "libvirt", "incus", "metal", "manual"]
    role: Role
    private_ip: str = Field(alias="privateIp")
    type: str | None = None  # hcloud server type, e.g. cx23
    ip: str | None = None  # public IP for manual/metal hosts
    metal: str | None = None  # libvirt: the hypervisor host it runs on
    vcpu: int | None = None
    memory: str | None = None


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Return whether `ip` falls inside the `cidr` block (False if either won't parse)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


_ENTRY_ROLES = frozenset({"edge", "all-in-one"})


def _check_domains(platform_domain: str, domains: list[str]) -> None:
    """Raise unless the platform domain is one of the managed domains."""
    if platform_domain not in domains:
        msg = f"platformDomain {platform_domain!r} must be one of domains {domains}"
        raise ValueError(msg)


def _check_unique(hosts: list[Host]) -> None:
    """Raise if any host name or private IP is duplicated."""
    names = [h.name for h in hosts]
    if len(names) != len(set(names)):
        msg = "hosts[].name must be unique"
        raise ValueError(msg)
    ips = [h.private_ip for h in hosts]
    if len(ips) != len(set(ips)):
        msg = "hosts[].privateIp must be unique"
        raise ValueError(msg)


def _check_entry_and_mesh(hosts: list[Host], mesh: str) -> None:
    """Raise unless there is exactly one entry-point host and mesh fits the count."""
    entry = [h for h in hosts if h.role in _ENTRY_ROLES]
    if len(entry) != 1:
        msg = "exactly one host must have role 'edge' or 'all-in-one'"
        raise ValueError(msg)
    if mesh == "none" and len(hosts) != 1:
        # VMs on a hypervisor's bridge need no mesh: they share the bridge with
        # the hypervisor host, which is the entry point. Any other multi-host
        # shape must declare a mesh to reach across hosts.
        bridge_hosts = [
            h for h in hosts if h.provider in {"incus", "libvirt"} or h.role == "hypervisor"
        ]
        if len(bridge_hosts) != len(hosts):
            msg = "mesh: none is only valid with a single host"
            raise ValueError(msg)


_SINGLETON_ROLES = frozenset({"app", "data"})


def _check_singleton_roles(hosts: list[Host]) -> None:
    """Raise unless placement-target roles are 1:1 with hosts (spec §3.1).

    `edge`/`all-in-one` are already exactly-one via `_check_entry_and_mesh`;
    `hypervisor` is exempt — placement never targets it, and the broker needs
    multi-metal to be legal. Multi-host roles are future work; the seam is a
    `selector:` on placement, not a redesign (§13).
    """
    for role in sorted(_SINGLETON_ROLES):
        named = [h.name for h in hosts if h.role == role]
        if len(named) > 1:
            msg = (
                f"at most one host may have role {role!r} "
                f"(placement is a singleton model today) — found: {', '.join(named)}"
            )
            raise ValueError(msg)


def _check_vm_hosts(hosts: list[Host]) -> None:
    """Raise unless every libvirt/incus host names an existing hypervisor host in `metal`."""
    hypervisors = {h.name for h in hosts if h.role == "hypervisor"}
    for h in hosts:
        if h.provider not in {"libvirt", "incus"}:
            continue
        if not h.metal:
            msg = f"host {h.name}: provider {h.provider} requires 'metal' (its hypervisor host)"
            raise ValueError(msg)
        if h.metal not in hypervisors:
            msg = f"host {h.name}: metal {h.metal!r} is not a hypervisor host in this org"
            raise ValueError(msg)


def _check_subnets(hosts: list[Host], network: Network) -> None:
    """Raise unless every host's private IP sits in its provider's declared subnet."""
    for h in hosts:
        if h.role == "hypervisor":
            # The hypervisor's privateIp is its management IP, not an app subnet.
            continue
        cloud = h.provider == "hcloud"
        subnet = network.cloud_subnet if cloud else network.vswitch_subnet
        if not _ip_in_cidr(h.private_ip, subnet):
            field = "cloudSubnet" if cloud else "vswitchSubnet"
            msg = f"host {h.name}: privateIp {h.private_ip} is not in {field} {subnet}"
            raise ValueError(msg)


class Org(BaseModel):
    """A validated nukorg/v1 Org manifest (`<org>/infra/nuklaut.org.yml`)."""

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nukorg/v1"] = Field(alias="apiVersion")
    kind: Literal["Org"]
    metadata: Metadata
    domains: list[str]
    platform_domain: str = Field(alias="platformDomain")
    acme_email: str = Field(alias="acmeEmail")
    network: Network | None = None
    hosts: list[Host]
    facilities: Facilities
    mesh: Literal["tailscale", "none"] = "none"
    overlays: list[str] = []

    @model_validator(mode="after")
    def _check_topology(self) -> Org:
        """Enforce the host-topology invariants the platform relies on.

        Raises:
            ValueError: On any violated invariant (unique names/IPs, exactly one
                entry-point host, mesh/host-count coupling, libvirt→hypervisor,
                at most one host per placement-target role, platformDomain membership,
                and private-IP subnet placement).
        """
        _check_domains(self.platform_domain, self.domains)
        _check_unique(self.hosts)
        _check_entry_and_mesh(self.hosts, self.mesh)
        _check_singleton_roles(self.hosts)
        _check_vm_hosts(self.hosts)
        if self.network is not None:
            _check_subnets(self.hosts, self.network)
        return self

    def host_for(self, role: str) -> Host | None:
        """The host carrying `role`, or None (placement-target roles are singletons)."""
        return next((h for h in self.hosts if h.role == role), None)


def validate_ingress_hosts(org: Org, manifest: Deployment | Facility) -> None:
    """Assert every ingress host in `manifest` ends on one of the org's domains.

    Args:
        org: The validated Org (its `domains` are the managed set).
        manifest: A deployment manifest whose ingress hosts must be covered.

    Raises:
        SystemExit: If any ingress host is not under a managed domain.
    """
    for ing in manifest.spec.ingress:
        if not any(ing.host == d or ing.host.endswith(f".{d}") for d in org.domains):
            sys.exit(f"nuk: ingress host {ing.host!r} is not under a managed domain {org.domains}")


def sh(*cmd: str, cwd: Path | None = None) -> None:
    """Run a command, raising on non-zero exit."""
    subprocess.run(cmd, cwd=cwd, check=True)  # noqa: S603  # fixed argv, no shell


def load(path: Path) -> Deployment | Facility:
    """Parse and validate a manifest file into a `Deployment` or a `Facility`.

    Args:
        path: Path to the manifest YAML.

    Returns:
        The validated manifest, carrying the raw parsed dict for the render
        functions.

    Raises:
        SystemExit: If the document is not a valid nuk/v1 Deployment or Facility.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        manifest = _MANIFEST_ADAPTER.validate_python(raw)
    except ValidationError:
        sys.exit(f"{path}: not a nuk/v1 Deployment or Facility")
    manifest._raw = raw  # noqa: SLF001  # stash wire-contract input on its own model
    return manifest


def resolve_manifest(path: Path) -> Path:
    """Back-compat manifest lookup: fall back to the legacy `.nuklaut/<name>`.

    The nuk manifest moved from `.nuklaut/deployment.yml` to a repo-root
    `deployment.yml`. Apps not yet migrated still keep it under `.nuklaut/`, so
    when `path` is absent, fall back to `<path.parent>/.nuklaut/<path.name>`;
    otherwise return `path` unchanged (its own not-found error still fires).
    """
    if not path.exists():
        legacy = path.parent / ".nuklaut" / path.name
        if legacy.exists():
            return legacy
    return path


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


# --- tenant registry (bartixcloud/infra/tenants.yml, contracts C2) ------------------
# The platform repo owns the schema and its validator. nuk models only the fields it
# consumes and re-checks the invariant its own isolation depends on: unique names and
# no two tenants claiming the same domain (spec §4 anti-hijack).

TENANTS_FILE = "tenants.yml"


class TenantRow(BaseModel):
    """One `tenants[]` row, as far as nuk reads it.

    `tenants.yml` is the shared platform registry (the runner broker's
    `bcx-gen-tenant-env` reads the same file and tolerates unknown keys). nuk models
    only `name` + the edge allowlist `domains`; any other field is ignored.
    """

    model_config = ConfigDict(extra="ignore")

    name: str = Field(pattern=r"^[a-z0-9-]+$")
    domains: list[str] = []
    edge: Literal["shared", "passthrough"] | None = None
    signer_principal: str | None = None


def _domains_overlap(x: str, y: str) -> bool:
    """Whether two domain entries can name the same host (`*.` = any depth, never the apex)."""
    x, y = x.lower(), y.lower()
    if x.startswith("*.") and y.startswith("*."):
        return x.endswith(y[1:]) or y.endswith(x[1:])
    if x.startswith("*."):
        return y.endswith(x[1:])
    if y.startswith("*."):
        return x.endswith(y[1:])
    return x == y


class TenantRegistry(BaseModel):
    """The `tenants:` list of tenants.yml."""

    tenants: list[TenantRow]

    @model_validator(mode="after")
    def _check_unique(self) -> TenantRegistry:
        """Refuse duplicate tenant names and any domain two tenants could both match.

        Raises:
            ValueError: On either violation.
        """
        names = [t.name for t in self.tenants]
        if len(names) != len(set(names)):
            msg = "tenants[].name must be unique"
            raise ValueError(msg)
        for i, a in enumerate(self.tenants):
            for b in self.tenants[i + 1 :]:
                for da in a.domains:
                    for db in b.domains:
                        if _domains_overlap(da, db):
                            msg = (
                                f"domains overlap between tenants {a.name!r} and {b.name!r}: "
                                f"{da!r} / {db!r}"
                            )
                            raise ValueError(msg)
        return self

    def get(self, name: str) -> TenantRow | None:
        """The row for tenant `name`, or None."""
        return next((t for t in self.tenants if t.name == name), None)


def load_tenants(tree: Path) -> TenantRegistry:
    """Parse `<tree>/tenants.yml` (the platform tree).

    Raises:
        SystemExit: If the file is unreadable or invalid.
    """
    path = tree / TENANTS_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        sys.exit(f"{path}: {e}")
    try:
        return TenantRegistry.model_validate(raw)
    except ValidationError as e:
        sys.exit(f"{path}: invalid tenants registry\n{e}")


def host_in_domains(host: str, domains: list[str]) -> bool:
    """Whether `host` is one of `domains` (spec §4 anti-hijack rule).

    An entry matches exactly, or — written `*.example.com` — matches any subdomain
    of example.com at any depth, never the apex itself.
    """
    h = host.lower()
    for d in (x.lower() for x in domains):
        if d.startswith("*."):
            if h.endswith(d[1:]):
                return True
        elif h == d:
            return True
    return False


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
    probe = f"urllib.request.urlopen('http://localhost:{port}{path}')"
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
    return DYNAMIC / f"{name}.yml"


def _db_env_path(app: str) -> Path:
    """An app's DB creds env-file — also the marker that nuk still tracks its database."""
    return SECRETS / f"{app}-db.env"


def _db_env_apps() -> list[str]:
    """Apps with a DB creds file, deployed or retained."""
    if not SECRETS.exists():
        return []
    return sorted(f.name.removesuffix("-db.env") for f in SECRETS.glob("*-db.env"))


def github_url(remote: str) -> str | None:
    """Normalise a git remote (ssh or https) to its github.com web URL, or None."""
    remote = remote.strip()
    m = re.match(r"git@github\.com:(.+?)(?:\.git)?$", remote) or re.match(
        r"https?://github\.com/(.+?)(?:\.git)?$", remote
    )
    return f"https://github.com/{m.group(1)}" if m else None


def git_origin(repo_path: str) -> str | None:
    """github.com web URL for repo_path's origin remote, or None if unavailable."""
    out = _git_try(repo_path, "config", "--get", "remote.origin.url")
    return github_url(out) if out else None


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
    spec_body = spec.get("spec") or {}
    src = spec_body.get("source") or {}
    origin = git_origin(repo_path) if repo_path else None
    if origin and not src.get("repo"):
        spec_body["source"] = {**src, "repo": origin}
        spec["spec"] = spec_body
        dest.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    else:
        shutil.copy(src_path, dest)


def _compose_file(spec: dict) -> str:
    """Read `compose.file` from a raw `spec` dict.

    Accepts the bare-string form (`compose: foo.yml`), the mapping form
    (`compose: {file: foo.yml}`), and a bare null key (`compose:`), which YAML
    parses to None and which `_NullTolerant` treats as absent elsewhere.
    """
    compose = spec.get("compose")
    if isinstance(compose, str):
        return compose
    if isinstance(compose, dict):
        return compose.get("file", "docker-compose.yml")
    return "docker-compose.yml"


def compose_args(name: str, spec: dict) -> list[str]:
    """Build the `docker compose` base argv for an app from its raw spec."""
    repo = _repo_dir(name)
    spec_body = spec.get("spec") or {}
    cf = _compose_file(spec_body)
    override = project_dir(name) / "compose.override.yml"
    args = ["docker", "compose", "-p", name, "-f", str(repo / cf)]
    if override.exists():
        args += ["-f", str(override)]
    for ref in resolve_env_from(spec_body):
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
    for envfile in spec.get("envFrom") or []:
        ref = envfile.get("secretRef") if isinstance(envfile, dict) else envfile
        if ref and Path(ref).exists():
            refs.append(ref)
    return refs


def build_override(  # noqa: C901, PLR0913, PLR0914, PLR0917  # frozen wire-contract API; one render pass
    name: str,  # noqa: ARG001  # kept for signature stability (frozen wire-contract API / tests)
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
    local_data: bool = True,
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
        publish_ip: When set (a worker with no local Traefik), ingress services
            PUBLISH their port on this private IP (so the edge Traefik reaches
            them over the cloud-network) instead of joining the local `edge`
            network. None (the default) => unchanged, edge-network behavior.
        local_data: True (default) joins the local external ``data`` docker
            network for DB services — correct when the DB is colocated on this
            host. False omits it: a CROSS-HOST database (spec §3.1) is reached
            over TCP at the data host's private IP, and no local ``data``
            network exists to join.

    Returns:
        The override doc, or None when no service needs any wiring.
    """
    env_from = env_from or []
    ingress_services = [ing["service"] for ing in ingress]
    db_targets = (list(ingress_services) if db_env else []) if db_services is None else db_services
    db_set = set(db_targets) if db_env else set()
    # Ingress order first, then any db-only (non-ingress) services, deduped.
    ordered = list(dict.fromkeys([*ingress_services, *db_targets]))
    # Worker edge-termination: collect the private-IP port bindings per service.
    # Bind on publish_ip (not 0.0.0.0) so the app stays reachable ONLY via the edge.
    publish_ports: dict[str, list[str]] = {}
    if publish_ip:
        for ing in ingress:
            svc, port = ing.get("service"), ing.get("port")
            if svc and port is not None:
                host_port = _published_port(ing)
                mapping = f"{publish_ip}:{host_port}:{port}"
                publish_ports.setdefault(svc, [])
                if mapping not in publish_ports[svc]:
                    publish_ports[svc].append(mapping)
    services: dict = {}
    for svc_name in ordered:
        is_ingress = svc_name in ingress_services
        is_db = svc_name in db_set
        # Publishing on a private IP replaces the (inert) local `edge` join.
        nets = (["edge"] if is_ingress and not publish_ip else []) + (
            ["data"] if is_db and local_data else []
        )
        env_files = [*env_from, *([db_env] if is_db else [])]
        svc: dict = {"networks": nets}
        if publish_ip and svc_name in publish_ports:
            svc["ports"] = publish_ports[svc_name]
        if env_files:
            svc["env_file"] = env_files
        services[svc_name] = svc
    if not services:
        return None
    networks: dict = {}
    if not publish_ip and any(s in ingress_services for s in services):
        networks["edge"] = {"external": True}
    if any(s in db_set for s in services) and local_data:
        networks["data"] = {"external": True}
    return {"services": services, "networks": networks}


def _published_port(ing: dict) -> int:
    """The host port a non-entry host publishes an ingress on: `hostPort`, else `port`.

    The publish (build_override) and the edge's backend (backend_address) must agree.
    """
    return ing.get("hostPort") or ing["port"]


def write_override(  # noqa: PLR0913, PLR0917  # thin writer over build_override's frozen API
    name: str,
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
    local_data: bool = True,
) -> None:
    """Render and write `compose.override.yml` for an app (no-op when empty)."""
    doc = build_override(name, ingress, db_env, env_from, db_services, publish_ip, local_data)
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
    cf = _compose_file(raw["spec"])
    path = _repo_dir(name) / cf
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


# The gates the pre-facility code hardcoded. Retained for the legacy all-in-one
# path — a single-host controller with no facilities dir — so its renders stay
# byte-identical (spec §12). A tree that ships facilities/ overrides it entirely;
# test_shipped_facilities_reproduce_the_default_vocabulary keeps the two in step.
# Keys are route CAPABILITY names; today `ingress[].auth: basic` names the capability `basic`.
DEFAULT_ROUTE_VOCAB: dict[str, list[str]] = {"basic": ["auth@file"]}


def _container_name(name: str, service: str, colour: str | None = None) -> str:
    """The runtime container name docker compose gives an app's service.

    No manifest sets `container_name`, so compose's DEFAULT naming applies:
    `<project>-<service>-<n>`. The single replicas nuk deploys always land on
    `-1`, and blue-green adds the colour profile between service and index. Both
    the router backend (write_ingress) and the health probe (`_apply_blue_green`)
    must name the same container, so both go through here.
    """
    return f"{name}-{service}{f'-{colour}' if colour else ''}-1"


def build_ingress(  # noqa: C901, PLR0912, PLR0914  # one router-build loop; clean extraction would obscure the per-field ordering
    name: str,
    ingress: list[dict],
    vocab: dict[str, list[str]],
    *,
    colour: str | None = None,
    dialect: str = "edge",
) -> dict | None:
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
            middleware. Backend URL logic is identical in both.

    Returns:
        The Traefik dynamic doc, or None when there is no ingress.
    """
    if not ingress:
        return None
    is_mesh = dialect == "mesh"
    entry_point = "mesh" if is_mesh else "websecure"
    routers, services, middlewares = {}, {}, {}
    for i, ing in enumerate(ingress):
        rid = f"{name}-{i}"
        router = {
            "rule": _rule(ing),
            "entryPoints": [entry_point],
            "service": rid,
            **({} if is_mesh else {"tls": {"certResolver": "letsencrypt"}}),
        }
        mw = []
        # ⚠ The refusals below are load-bearing. The chain this replaced once had no
        #   `else`, and an unrecognised value fell through to a router with no auth
        #   middleware and no error — a security control failing OPEN. The lookup
        #   keeps that closed and widens it: an undeclared capability, and a
        #   capability whose chain is empty, are BOTH refusals (spec §5.4).
        want = ing.get("auth")
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
        if ing.get("path") and ing.get("stripPrefix"):
            sid = f"{rid}-strip"
            middlewares[sid] = {"stripPrefix": {"prefixes": [ing["path"]]}}
            mw.append(sid)
        # Every app router inherits the controller-wide branded maintenance page:
        # 502-504 from the backend → the maintenance service (see global.yml). The
        # middleware is provider-qualified (@file) since it lives in global.yml.
        # Only the edge ships that file; the mesh dialect leaves it off.
        if not is_mesh:
            mw.append("maintenance-errors@file")
        if mw:
            router["middlewares"] = mw
        if "priority" in ing:
            router["priority"] = ing["priority"]
        routers[rid] = router
        # `address` (remote host:port) bypasses the local edge-network container
        # naming convention entirely — used for backends on another host (e.g. a
        # libvirt VM reached over the private vswitch/cloud-network).
        if ing.get("address"):
            backend = ing["address"]
        else:
            backend = f"{_container_name(name, ing['service'], colour)}:{ing['port']}"
        services[rid] = {"loadBalancer": {"servers": [{"url": f"http://{backend}"}]}}
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
                "entryPoints": [entry_point],
                "service": rid,
                "middlewares": [rdid],
                **({} if is_mesh else {"tls": {"certResolver": "letsencrypt"}}),
            }
    http = {"routers": routers, "services": services}
    if middlewares:
        http["middlewares"] = middlewares
    return {"http": http}


def write_ingress(
    name: str,
    ingress: list[dict],
    vocab: dict[str, list[str]],
    *,
    colour: str | None = None,
    dialect: str = "edge",
) -> None:
    """Render and write the Traefik dynamic file for an app (removes it if empty).

    `colour` threads the blue-green colour into `build_ingress` (see there).
    `dialect` selects the edge or mesh entrypoint/TLS flavour (see there).
    """
    target = _router_file(name)
    doc = build_ingress(name, ingress, vocab, colour=colour, dialect=dialect)
    if doc is None:
        target.unlink(missing_ok=True)
        return
    text = yaml.safe_dump(doc)
    # Every write is an fsnotify event that makes Traefik rebuild its whole dynamic
    # config, and the loop re-applies every cycle — skip identical content.
    try:
        if target.read_text() == text:
            return
    except OSError:
        pass
    target.write_text(text)


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env-file (blank lines and `#` comments skipped).

    Raises:
        OSError: If the file cannot be read.
    """
    out: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def read_self() -> tuple[str, str | None]:
    """Return (role, private_ip) for THIS host from /etc/nuklaut/host.env.

    cloud-init writes ROLE + PRIVATE_IP there (world-readable, no secrets). When
    the file is absent or unparseable — a legacy single-host controller — this
    returns ("all-in-one", None): an entry role, so apply keeps writing ingress
    locally and every existing render stays byte-identical.
    """
    try:
        env = _read_env_file(HOST_ENV)
    except OSError:
        env = {}
    return env.get("ROLE") or "all-in-one", env.get("PRIVATE_IP") or None


def read_tenant() -> str | None:
    """Return TENANT from /etc/nuklaut/host.env (contracts C3).

    None for platform VMs (`TENANT=` empty) and for hosts without the key or the file.
    """
    try:
        env = _read_env_file(HOST_ENV)
    except OSError:
        env = {}
    return env.get("TENANT") or None


# --- signed-tag trust ----------------------------------------------------------
# Ported from infra/tf-incus/reconcile.sh:74-120, which guards the LAYER-1 loop
# (terraform, nuroot only, bash). This is the LAYER-3 loop (nuk manifests, every
# platform host, Python). The logic is duplicated on purpose — sharing it would
# mean shipping bash into nuk or terraform onto the fleet — so keep the two in
# step: a fix to either belongs in both. Both bugs the bash version grew during
# host verification (2026-08-15) are re-encoded as tests here.


def _git(repo: Path | str, *args: str, timeout: float | None = None) -> str:
    """`git -C repo <args>` → stdout, stripped.

    Raises:
        subprocess.CalledProcessError: On non-zero exit.
        subprocess.TimeoutExpired: If `timeout` elapses.
    """
    out = subprocess.run(  # noqa: S603  # fixed argv, no shell
        ["git", "-C", str(repo), *args],  # noqa: S607  # git on PATH
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return out.stdout.strip()


def _git_try(repo: Path | str, *args: str) -> str | None:
    """Best-effort `_git` for read-only lookups: None on failure or empty output."""
    try:
        return _git(repo, *args, timeout=4) or None
    except (subprocess.SubprocessError, OSError):
        return None


def _is_ancestor(repo: Path, a: str, b: str) -> bool:
    """Whether commit-ish `a` is an ancestor of commit-ish `b`."""
    return (
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", a, b],  # noqa: S607
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )


def verify_tag(repo: Path, signers: Path, tag: str) -> bool:
    """Whether `tag`'s signature verifies against the allowed-signers file.

    `gpg.format=ssh` and the signers file are passed with `-c` rather than read
    from the repo's own config: a repo that names its own trust anchor does not
    have one.
    """
    return (
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            [  # noqa: S607  # git on PATH
                "git",
                "-C",
                str(repo),
                "-c",
                "gpg.format=ssh",
                "-c",
                f"gpg.ssh.allowedSignersFile={signers}",
                "verify-tag",
                tag,
            ],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )


def resolve_signed_tag(repo: Path, signers: Path) -> str | None:
    """The newest `v*` tag whose signature verifies, or None if none does.

    Iterates ALL candidates rather than verifying only the newest: one unsigned
    tag pushed by anyone with write access would otherwise be a denial of service
    against the whole loop.

    Among verifying candidates it prefers the topological DESCENDANT, not the
    creatordate-newest. `creatordate` has one-second granularity and for-each-ref
    breaks ties on refname, which is not release order — v2.10.0 sorts below
    v2.9.0, and two tags cut in the same second resolve arbitrarily. Taking the
    first verifying hit pinned the loop to an OLDER tag forever, reporting "no
    changes" every cycle while a newer signed tag sat unapplied (found on the host
    2026-08-15, v2.0.1 shadowing v2.1.0). Tags on unrelated histories fall back to
    the creatordate-newest, which is the best available answer.
    """
    try:
        refs = _git(
            repo, "for-each-ref", "--sort=-creatordate", "--format=%(refname:short)", "refs/tags/v*"
        ).splitlines()
    except subprocess.CalledProcessError:
        return None
    best: str | None = None
    for tag in (t.strip() for t in refs if t.strip()):
        if not verify_tag(repo, signers, tag):
            continue
        if best is None:
            best = tag
            continue
        if _is_ancestor(repo, f"{best}^{{commit}}", f"{tag}^{{commit}}") and not _is_ancestor(
            repo, f"{tag}^{{commit}}", f"{best}^{{commit}}"
        ):
            best = tag
    return best


def assert_not_downgrade(repo: Path, tag: str, state: Path) -> None:
    """Refuse to move to a tag that is not a descendant of the last applied one.

    Signature verification alone does not prevent a downgrade: someone with write
    access can DELETE newer tags, walking the fleet back onto older, legitimately
    signed state.

    The state file records "<tag> <sha>" and this compares the SHA, never the tag
    name. Recording only the name was a hole: the downgrade attack IS tag
    deletion, so resolving the previous tag by name fails exactly when the guard
    is needed, and the guard then permitted the rollback it existed to stop.

    An unresolvable previous SHA (rewritten history, gc'd commit) is ambiguous,
    and ambiguity here is indistinguishable from an attack — so it refuses and
    asks for a human.

    Raises:
        ValueError: On a downgrade or an unresolvable previous commit.
    """
    if not state.exists():
        return
    parts = state.read_text(encoding="utf-8").split()
    if len(parts) < 2:  # noqa: PLR2004  # "<tag> <sha>"
        return
    prev_sha = parts[1]
    try:
        _git(repo, "rev-parse", "-q", "--verify", f"{prev_sha}^{{commit}}")
    except subprocess.CalledProcessError:
        msg = (
            f"last applied commit {prev_sha} is unknown to this repo (rewritten history?) — "
            f"resolve by hand"
        )
        raise ValueError(msg) from None
    if not _is_ancestor(repo, prev_sha, f"{tag}^{{commit}}"):
        msg = (
            f"{tag} is not a descendant of last applied {prev_sha}: the newest verifying tag "
            f"went BACKWARDS — a newer tag was deleted, or history was rewritten. "
            f"A tag deletion can walk the fleet backwards. Resolve by hand."
        )
        raise ValueError(msg)


def record_applied(tag: str, commit: str, state: Path) -> None:
    """Record "<tag> <sha>" as the last applied state. The SHA is the guard's input."""
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(f"{tag} {commit}\n", encoding="utf-8")


# --- sources (contracts C3) ----------------------------------------------------------

# The platform source is the one that applies `facilities`; every other source is a tenant
# and its name is the tenant name.
SourceApply = Literal["facilities", "deployments", "databases", "routes"]


class SourceEntry(BaseModel):
    """One `sources[]` entry of /etc/nuklaut/sources.yml."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9-]+$")
    repo: str
    deploy_key: Path
    apply: list[SourceApply] = Field(min_length=1)

    @property
    def is_platform(self) -> bool:
        """The platform source is the one source allowed to apply facilities."""
        return "facilities" in self.apply


class SourcesFile(BaseModel):
    """/etc/nuklaut/sources.yml."""

    model_config = ConfigDict(extra="forbid")

    sources: list[SourceEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> SourcesFile:
        """Unique names; exactly one platform source, which never applies databases.

        Raises:
            ValueError: On a violated rule.
        """
        names = [s.name for s in self.sources]
        if len(names) != len(set(names)):
            msg = "sources[].name must be unique"
            raise ValueError(msg)
        platform = [s for s in self.sources if s.is_platform]
        if len(platform) != 1:
            msg = (
                f"exactly one source must apply `facilities` (the platform source) — "
                f"found {[s.name for s in platform] or 'none'}"
            )
            raise ValueError(msg)
        if "databases" in platform[0].apply:
            msg = "the platform source cannot apply `databases` (tenant sources only)"
            raise ValueError(msg)
        return self

    def ordered(self) -> list[SourceEntry]:
        """The platform source first, then tenants in file order."""
        return sorted(self.sources, key=lambda s: not s.is_platform)


def load_sources(path: Path) -> SourcesFile:
    """Parse and validate sources.yml.

    Raises:
        ValueError: If the file is unreadable or invalid (the message names the file).
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return SourcesFile.model_validate(raw)
    except (OSError, ValidationError, yaml.YAMLError) as e:
        msg = f"{path}: {e}"
        raise ValueError(msg) from None


def git_ssh_command(key: Path) -> str:
    """GIT_SSH_COMMAND that authenticates with exactly one deploy key.

    IdentitiesOnly stops ssh offering agent or default keys; the host key comes from
    KNOWN_HOSTS only, so a fetch never trusts on first use.
    """
    return (
        f"ssh -i {shlex.quote(str(key))} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes "
        f"-o UserKnownHostsFile={shlex.quote(str(KNOWN_HOSTS))} -o BatchMode=yes"
    )


def source_state_dir(state_dir: Path, name: str) -> Path:
    """`<state_dir>/sources/<name>` — the bare repo and last-applied-tag."""
    return state_dir / "sources" / name


# The branch whose head the unsigned (branch-mode) tree is archived from. A
# sources.yml entry carries only a repo, and a bare repo has no default fetch
# refspec, so the branch must be named explicitly. `Source.branch` defaults to
# this; every fleet repo's main line is `main`.
SOURCE_BRANCH = "main"


def sync_source(src: SourceEntry, signers_dir: Path, state_dir: Path) -> tuple[str, str, str]:
    """Fetch one source, verify it against its own signers file, guard against downgrade.

    The repo is bare: the tree is only ever read through `git archive` of a verified
    commit, never from a worktree.

    Both refs are fetched in one round trip: the signed `v*` tags (always verified
    against the source's own signers) and the branch head (`SOURCE_BRANCH`). The
    branch head is UNSIGNED — branch mode is a non-prod opt-in, so it is not
    signature-checked here and the tag downgrade guard does not apply to it.

    Returns:
        The verified tag, its commit SHA, and the branch head's SHA.

    Raises:
        ValueError: With the refusal reason; nothing but fetched objects changes.
    """
    signers = signers_dir / src.name
    if not signers.is_file():
        msg = f"trust anchor {signers} (allowed_signers.d/{src.name}) is missing or unreadable"
        raise ValueError(msg)
    sdir = source_state_dir(state_dir, src.name)
    repo = sdir / "repo"
    if not (repo / "HEAD").is_file():
        repo.mkdir(parents=True, exist_ok=True)
        _git(repo, "init", "--bare", "-q")
    try:
        _git(repo, "remote", "set-url", "origin", src.repo)
    except subprocess.CalledProcessError:
        _git(repo, "remote", "add", "origin", src.repo)
    # The tag refspec prunes a tag deleted upstream (the downgrade guard must not
    # compare against a tag that exists nowhere else). It is spelled out rather
    # than `--prune-tags` because an explicit branch refspec on the command line
    # defeats `--prune-tags` (git does not prune tags then), which would silently
    # disable the downgrade guard. The branch refspec lands in a durable ref (not
    # FETCH_HEAD) so the head can be archived by SHA right after. One round trip.
    branch_ref = f"refs/remotes/origin/{SOURCE_BRANCH}"
    proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
        [  # noqa: S607  # git on PATH
            "git",
            "-C",
            str(repo),
            "fetch",
            "--prune",
            "--force",
            "origin",
            f"refs/heads/{SOURCE_BRANCH}:{branch_ref}",
            "refs/tags/*:refs/tags/*",
        ],
        env={**os.environ, "GIT_SSH_COMMAND": git_ssh_command(src.deploy_key)},
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or [f"exit {proc.returncode}"])[-1]
        msg = f"git fetch failed ({detail}) — no network, no change"
        raise ValueError(msg)
    tag = resolve_signed_tag(repo, signers)
    if tag is None:
        msg = f"no v* tag verifies against {signers}"
        raise ValueError(msg)
    # The downgrade guard is TAG-MODE ONLY: it compares the newest signed tag against
    # the last applied one and never the branch head. The branch head is fetched and
    # archived for unsigned deployments, but a branch head that is older than the
    # newest tag is legitimate (the tag may have been cut on another branch), so it
    # must not feed this guard nor trip it.
    assert_not_downgrade(repo, tag, sdir / "last-applied-tag")
    return (
        tag,
        _git(repo, "rev-parse", f"{tag}^{{commit}}"),
        _git(repo, "rev-parse", branch_ref),
    )


# --- the convergence loop ------------------------------------------------------
# One per host, started by the poke (seconds) and by a 6-12 h liveness floor. The
# floor is a LIVENESS GUARANTEE, not a control loop: without it a single lost poke
# — host down during a deploy, service crash, network blip — leaves a host
# silently stale forever (spec §7.2).


@contextmanager
def converge_lock(state_dir: Path) -> Iterator[bool]:
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


def provision_remote_databases(tree: Path, role: str, facilities: list[Facility]) -> list[dict]:
    """Provision every deployment's databases on this host IF it owns the capability.

    The placement-gate exception (spec §3.1): a deployment placed `app` is a
    no-op on the `data` host for containers and ingress, but its `spec.databases`
    fragment must still be provisioned HERE — this is the only host with a local
    `nuk-postgres`. Scoped to provisioning: nothing else about the manifest runs.

    Deterministic derivation makes this loop-stable: the same seed yields the
    same password, so re-running converges to a no-op rather than rotating.
    """
    provider = env_facility(facilities, _DATABASES_CAPABILITY)
    if provider is None or not placement_matches(provider, role):
        return []
    out: list[dict] = []
    for path in sorted((tree / DEPLOYMENT_DIR).glob("*.yml")):
        try:
            manifest = load(path)
        except SystemExit as e:
            out.append(_result(path.name, "Database", "failed", _exit_reason(e, "load failed")))
            continue
        if manifest.kind != "Deployment":
            continue
        dbs = manifest.raw.get("spec", {}).get("databases") or {}
        if not (dbs.get("postgres") or dbs.get("redis")):
            continue
        name = manifest.metadata.name
        entry = _result(name, "Database")
        try:
            # remote_ip=None → the LOCAL data stack is provisioned, on this host.
            provision_databases(name, dbs, facilities, remote_ip=None)
        except (SystemExit, subprocess.CalledProcessError) as e:
            # One app's provisioning failure must not abort the cycle (spec §7.5):
            # `_psql` uses check=True, so a SQL failure (disk full, role/db
            # conflict, container hiccup) surfaces as CalledProcessError, not
            # SystemExit. The data host still writes converge-status.json.
            entry["result"] = "failed"
            if isinstance(e, SystemExit):
                entry["error"] = _exit_reason(e, "provision failed")
            else:
                entry["error"] = f"provision failed: {e}"
        out.append(entry)
    return out


def _result(name: str, kind: str, result: str = "ok", error: str | None = None) -> dict:
    """One converge-status manifest entry (spec §7.6)."""
    return {"name": name, "kind": kind, "result": result, "error": error}


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


def apply_tree(ctx: TreeContext) -> list[dict]:
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
        One `{"name", "kind", "result", "error"}` entry per manifest this host
        owns, facilities first, each directory in filename order. `result` is
        "ok", "failed", or "refused".
    """
    tree, role = ctx.tree, ctx.role
    results: list[dict] = []
    failed_caps: set[str] = set()
    for kind, directory in (("Facility", FACILITY_DIR), ("Deployment", DEPLOYMENT_DIR)):
        if directory not in ctx.apply:
            continue
        for path in sorted((tree / directory).glob("*.yml")):
            try:
                manifest = load(path)
            except SystemExit as e:
                results.append(_result(path.name, kind, "failed", _exit_reason(e, "load failed")))
                continue
            if manifest.kind != kind or not placement_matches(manifest, role):
                continue
            apply_path = path
            if isinstance(manifest, Deployment):
                poisoned = consumes(manifest) & failed_caps
                if poisoned:
                    reason = (
                        f"consumes {sorted(poisoned)} from a facility that "
                        f"failed its health gate this cycle (spec §7.5)"
                    )
                    results.append(_result(manifest.metadata.name, kind, "refused", reason))
                    continue
                apply_path = _deployment_tree(ctx, manifest, path)
            # A signed (non-unsigned) deployment must BUILD the signed tag, not the
            # branch head its clone would otherwise follow: pin the clone to the
            # tag commit. An unsigned deployment stays on the branch head. A context
            # without a recorded tag commit (hand-run `for_path`, or Task 10's
            # `build()` asymmetry with `commits={}`) degrades to today's behaviour —
            # no pin — rather than raising.
            pin_commit = (
                ctx.commits.get("tag")
                if isinstance(manifest, Deployment) and not manifest.spec.source.unsigned
                else None
            )
            entry = _result(manifest.metadata.name, kind)
            try:
                cmd_apply(apply_path, None, ctx=ctx, pin_commit=pin_commit)
            except (SystemExit, ValueError, subprocess.CalledProcessError, OSError) as e:
                entry["result"] = "failed"
                entry["error"] = (
                    _exit_reason(e, "apply failed") if isinstance(e, SystemExit) else str(e)
                )
                if isinstance(manifest, Facility):
                    failed_caps |= _provided_capabilities(manifest)
            results.append(entry)
    # The placement exception (spec §3.1) runs in addition to the filter above: a
    # `{placement: app}` deployment is a container/ingress no-op here but its
    # `spec.databases` fragment is still this host's job when it owns the
    # facility. A deployment the loop already produced (applied, refused, failed)
    # was provisioned by `cmd_apply` itself — the sweep must not double it.
    handled = {r["name"] for r in results if r["kind"] == "Deployment"}
    results.extend(
        r
        for r in provision_remote_databases(tree, role, ctx.facilities)
        if r["name"] not in handled
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
    if not DEPLOYS.is_dir():
        return []
    declared: set[str] = set()
    for tree in trees:
        declared |= _declared_names(tree)
    return sorted(p.name for p in DEPLOYS.iterdir() if p.is_dir() and p.name not in declared)


def _atomic_write(path: Path, text: str) -> None:
    """Write `text` so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)


def write_converge_status(  # noqa: PLR0913  # one status field per keyword; a dataclass buys nothing here
    path: Path,
    *,
    role: str,
    tenant: str | None,
    sources: dict[str, dict],
    warnings: list[str],
    logging: dict | None = None,
    error: str | None = None,
) -> None:
    """Record the cycle's outcome (spec §7.6, contracts C3).

    `sources` maps each source name to its block `{result, error, tag, commit, apply,
    manifests, rendered, refusedRoutes}`. `logging` is the LOGGING pipeline's own health —
    info-only (spec §14.3): recorded, never a per-manifest result, never a failure
    condition; absent for non-edge cycles. `error` is set when the cycle could not even
    start (an unreadable sources.yml), so a failure is still a status, not silence.

    Consumed by `drift.sh` and by `nuk status`.
    """
    payload: dict = {
        "role": role,
        "tenant": tenant,
        "appliedAt": _iso_utc_now(),
        "reapWarnings": warnings,
        "sources": sources,
    }
    if logging is not None:
        payload["logging"] = logging
    if error is not None:
        payload["error"] = error
    _atomic_write(path, json.dumps(payload, indent=2) + "\n")


def read_converge_status(path: Path = CONVERGE_STATUS) -> dict | None:
    """The last recorded cycle, or None if absent/unreadable/malformed."""
    data = _read_json_safe(path)
    return data if isinstance(data, dict) else None


_SOURCE_FAILURES = (ValueError, SystemExit, subprocess.CalledProcessError, OSError)


def _prepare_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: SourceEntry,
    block: dict,
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
    block.update(tag=tag, commit=tag_sha)
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
    )


def _apply_source(src: SourceEntry, ctx: TreeContext, block: dict, state_dir: Path) -> None:
    """Apply a prepared source: manifests, then routes; record it applied only if all went well."""
    block["manifests"] = apply_tree(ctx)
    if "routes" in src.apply and ctx.role in _ENTRY_ROLES:
        routes = render_routes(ctx)
        block["rendered"] = routes.rendered
        block["refusedRoutes"] = routes.refused
    record_applied(
        block["tag"], block["commit"], source_state_dir(state_dir, src.name) / "last-applied-tag"
    )


def _refuse(src: SourceEntry, block: dict, e: BaseException) -> None:
    block["result"] = "refused"
    block["error"] = _exit_reason(e, "converge refused") if isinstance(e, SystemExit) else str(e)
    print(f"REFUSING source {src.name}: {block['error']}", file=sys.stderr)


def _converge_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: SourceEntry,
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
    scratch: Path,
    platform: Path | None,
) -> tuple[dict, TreeContext | None]:
    """Converge ONE source; never raises for a source-level failure.

    Returns:
        The source's status block, and its TreeContext once the tree is verified and archived
        (None when that failed, or when the platform tree is incomplete) — the platform's
        context is what tenant sources build on. `result` is "refused" on any failure here;
        manifests that fail individually inside `apply_tree` are recorded in `manifests` and do
        not refuse the source (spec §7.5). `last-applied-tag` moves only when the whole source
        succeeded.
    """
    block: dict = {
        "result": "ok",
        "error": None,
        "tag": None,
        "commit": None,
        "apply": list(src.apply),
        "manifests": [],
        "rendered": [],
        "refusedRoutes": [],
    }
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
                f"the platform tree at {block['tag']} lacks {DEFAULT_ORG_FILE} — "
                f"backends and routes resolve from it and cannot be guessed"
            )
            raise ValueError(msg)  # noqa: TRY301  # same refusal path as every other failure here
    except _SOURCE_FAILURES as e:
        _refuse(src, block, e)
        return block, None
    try:
        _apply_source(src, ctx, block, state_dir)
    except _SOURCE_FAILURES as e:
        _refuse(src, block, e)
    return block, ctx


def _logging_status(role: str, platform_ctx: TreeContext | None) -> dict | None:
    """The LOGGING pipeline's own health (spec §14.3): info-only, edge cycles only."""
    if role != "edge" or platform_ctx is None:
        return None
    facility = env_facility(platform_ctx.facilities, "logs")
    if facility is None:
        return None
    reason = facility_health(facility)
    return {"healthy": reason is None, "detail": reason or "ok"}


def _run_cycle(  # noqa: PLR0913  # one keyword per cycle input
    sources: list[SourceEntry],
    blocks: dict[str, dict],
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
) -> tuple[list[str], dict | None, bool]:
    """Converge every source, platform first; fill `blocks`.

    Returns:
        (orphan warnings, logging status, whether every source converged).
    """
    with tempfile.TemporaryDirectory(dir=state_dir, prefix="run.") as scratch:
        platform_ctx: TreeContext | None = None
        trees: list[Path] = []
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
                trees.append(ctx.tree)
                platform_ctx = ctx if src.is_platform else platform_ctx
        clean = all(b["result"] == "ok" for b in blocks.values())
        # A refused source has no tree this cycle, so its apps would all read as orphans;
        # only a clean cycle can tell what is really undeclared.
        warnings = reap_report(*trees) if clean else []
        return warnings, _logging_status(role, platform_ctx), clean


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
        blocks: dict[str, dict] = {}
        warnings: list[str] = []
        logging_status: dict | None = None
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
                warnings, logging_status, clean = _run_cycle(
                    sources,
                    blocks,
                    role=role,
                    self_ip=self_ip,
                    signers_dir=signers_dir,
                    state_dir=state_dir,
                )
                code = 0 if clean else 1
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


def placement_matches(manifest: Deployment | Facility, role: str) -> bool:
    """Whether THIS host, with `role`, is the one that runs `manifest`.

    The convergence loop hands every host the same tree; each applies the subset
    it owns. A manifest placed elsewhere is another host's job, not an error —
    hence a clean no-op rather than a failure (spec §5.4).

    Two documented exceptions match:
      * no `placement` at all — a manifest written before placement existed.
        It applies wherever it is run, exactly as it did before.
      * role `all-in-one` — a real composition of edge + data + app (spec §3.1),
        so it owns every placement.
    """
    placement = manifest.spec.placement
    if placement is None or role == "all-in-one":
        return True
    return placement.role == role


# Facility manifests live in <tree>/facilities/*.yml, where <tree> is the git tree
# the convergence loop pulled. Vocabulary comes from git, not runtime discovery —
# a HARD constraint, not a preference (spec §5.3): the edge renders routers for
# apps it does not run, so the host rendering a router is not necessarily the host
# running the facility, and a host-local registry cannot answer.
FACILITY_DIR = "facilities"


def load_facilities(tree: Path, *, lenient: bool = False) -> list[Facility]:
    """Load every `kind: Facility` manifest in `<tree>/facilities/*.yml`.

    A tree with no facilities dir yields no facilities — the empty vocabulary.
    That is not an error here; it becomes one at lookup time, when a router asks
    for a capability nobody declared (spec §5.4).

    Args:
        tree: Root of the manifest tree (the git checkout the loop pulled).
        lenient: Skip a malformed file instead of exiting. The converge loop builds
            its context this way so one broken facility is recorded as that
            manifest's failure by `apply_tree` and does not stop the rest (spec §7.5).

    Returns:
        The facilities, ordered by filename for a deterministic vocabulary.
    """
    fdir = tree / FACILITY_DIR
    if not fdir.is_dir():
        return []
    out: list[Facility] = []
    for p in sorted(fdir.glob("*.yml")):
        try:
            m = load(p)
        except SystemExit:
            if not lenient:
                raise
            continue
        if isinstance(m, Facility):
            out.append(m)
    return out


def route_vocabulary(facilities: list[Facility]) -> dict[str, list[str]]:
    """Map each declared route capability to its middleware chain.

    Order within a chain is the facility's declaration order: outer→inner, the
    same order the hardcoded default chain uses.

    Raises:
        SystemExit: If two facilities declare the same capability. A closed
            vocabulary with two answers is not closed; picking one silently
            would let a manifest added to the tree shadow the real gate.
    """
    vocab: dict[str, list[str]] = {}
    for f in facilities:
        route = f.spec.provides.route
        if route is None:
            continue
        if route.capability in vocab:
            sys.exit(
                f"nuk: route capability {route.capability!r} is declared by more than one "
                f"facility (second: {f.metadata.name!r}). Refusing an ambiguous vocabulary."
            )
        vocab[route.capability] = list(route.middlewares)
    return vocab


def env_facility(facilities: list[Facility], capability: str) -> Facility | None:
    """The facility declaring `provides.env.capability == capability`, if any."""
    for f in facilities:
        env = f.spec.provides.env
        if env is not None and env.capability == capability:
            return f
    return None


# App deployments live in <tree>/deployments/*.yml. The edge enumerates this dir
# to render a router for every one of them; before this, placement was implicit —
# "whichever host someone ran `nuk apply` on", or converge.sh's retired APPS variable.
DEPLOYMENT_DIR = "deployments"


def load_deployments(tree: Path) -> list[Deployment]:
    """Load every `kind: Deployment` manifest in `<tree>/deployments/*.yml`."""
    ddir = tree / DEPLOYMENT_DIR
    if not ddir.is_dir():
        return []
    return [m for p in sorted(ddir.glob("*.yml")) if isinstance(m := load(p), Deployment)]


def _tree_root(manifest_path: Path) -> Path:
    """The manifest tree root that one manifest path belongs to.

    The shipped layout puts manifests one level INSIDE the tree root:
    `<tree>/facilities/<name>.yml` and `<tree>/deployments/<name>.yml`. Taking a
    manifest's own parent as the tree root therefore looked for
    `<tree>/deployments/facilities/` — a directory that never exists — so
    load_facilities silently returned [], the git-sourced vocabulary was
    unreachable in production, and the `databases` capability guard refused
    every Deployment whose facility was sitting right there in
    `<tree>/facilities/`.

    A manifest applied bare (not under either directory) IS the tree root's own
    child already — a hand-run `nuk apply ./deployment.yml`, and every
    single-host tree predating the facilities layout.

    Args:
        manifest_path: Path to one manifest file.

    Returns:
        The resolved tree root to hand load_facilities / load_deployments.
    """
    parent = manifest_path.resolve().parent
    return parent.parent if parent.name in {FACILITY_DIR, DEPLOYMENT_DIR} else parent


# What one source may change on this host (contracts C3 `sources[].apply`).
APPLY_ALL = frozenset({"facilities", "deployments", "databases", "routes"})


@dataclass(frozen=True)
class TreeContext:
    """Everything one source's apply needs besides its own manifests.

    `facilities` and `org` always come from the PLATFORM tree (a tenant source
    ships neither — it must not be able to redefine the route vocabulary or the
    topology); `tree`, `tenant` and `apply` describe the source being applied.
    `tenant` is None for the platform source.
    """

    tree: Path
    role: str
    self_ip: str | None
    tenant: str | None
    apply: frozenset[str]
    facilities: list[Facility]
    org: Org | None
    tenants: TenantRegistry | None
    # Both refs one source was archived at (Task 10): the signed tag's tree and
    # the branch head's tree, keyed "tag"/"branch". `tree` stays the tag tree (a
    # signed deployment's). Task 11 picks per deployment from `trees`/`commits`.
    trees: dict[Literal["tag", "branch"], Path] = field(default_factory=dict)
    commits: dict[Literal["tag", "branch"], str] = field(default_factory=dict)

    @classmethod
    def build(  # noqa: PLR0913  # one field per attribute; a wrapper object buys nothing
        cls,
        tree: Path,
        role: str,
        self_ip: str | None,
        tenant: str | None,
        apply: frozenset[str],
        *,
        platform: Path | None = None,
        trees: dict[Literal["tag", "branch"], Path] | None = None,
        commits: dict[Literal["tag", "branch"], str] | None = None,
    ) -> TreeContext:
        """Load the platform-wide inputs from `platform` (default: `tree` itself)."""
        base = platform or tree
        org_path = base / DEFAULT_ORG_FILE
        tenants_path = base / TENANTS_FILE
        return cls(
            tree=tree,
            role=role,
            self_ip=self_ip,
            tenant=tenant,
            apply=apply,
            facilities=load_facilities(base, lenient=True),
            org=load_org(org_path) if org_path.is_file() else None,
            tenants=load_tenants(base) if tenants_path.is_file() else None,
            trees=trees if trees is not None else {"tag": tree},
            commits=commits if commits is not None else {},
        )

    @classmethod
    def for_path(cls, manifest_path: Path) -> TreeContext:
        """The context of a hand-run `nuk apply <manifest>`: this host, the manifest's own tree."""
        role, self_ip = read_self()
        return cls.build(_tree_root(manifest_path), role, self_ip, None, APPLY_ALL)


# The app host's router facility listens for plain-HTTP ingress from the edge on
# this port (infra: the `router` facility, placement {role: app}). When present,
# app deployments are fronted by it rather than dialled on their published port.
ROUTER_PORT = 8443


def backend_address(
    org: Org, manifest: Deployment, ing: dict, *, router_present: bool = False
) -> str:
    """Where the edge should send traffic for one ingress entry.

    An explicit `address` (a backend the org does not manage) passes through.
    Otherwise the backend is the private IP of the org's host for this
    deployment's `placement.role`, on the published port — the port
    build_override publishes, which is `hostPort` when set and `port` otherwise.

    When the fleet runs the `router` facility, an app-role deployment is instead
    fronted by that router on `ROUTER_PORT`: the app host's Traefik terminates the
    route, so the edge dials the router, not the container's published port.

    Raises:
        ValueError: If the deployment has no placement (the edge cannot guess
            which host runs it), or the org declares no host with that role.
    """
    if ing.get("address"):
        return ing["address"]
    placement = manifest.spec.placement
    if placement is None:
        msg = (
            f"{manifest.metadata.name}: has ingress but no spec.placement — the edge "
            f"cannot resolve a backend without knowing which host runs it."
        )
        raise ValueError(msg)
    host = org.host_for(placement.role)
    if host is None:
        msg = (
            f"{manifest.metadata.name}: placement.role={placement.role!r} but the org "
            f"manifest declares no host with role {placement.role!r}."
        )
        raise ValueError(msg)
    if router_present and placement.role == "app":
        return f"{host.private_ip}:{ROUTER_PORT}"
    return f"{host.private_ip}:{_published_port(ing)}"


# The prefix the deleted delivery path used to scope its rsync --delete. Files
# carrying it are the only thing this codebase ever removes without being asked:
# a stale worker-<name>.yml and a freshly-rendered <name>.yml define the SAME
# router key (ids are f"{name}-{i}"), Traefik picks between them
# nondeterministically, and a stale file predating an `auth:` addition could win.
_LEGACY_ROUTER_PREFIX = "worker-"


def reap_legacy_worker_routers(protected: set[str] | None = None) -> list[str]:
    """Remove routers the retired cross-host delivery path left on the edge.

    Bounded and one-time: scoped to the `worker-` prefix, so the edge's native
    routers (global.yml, oauth.yml, maintenance) are untouched — the same scope
    converge.sh's `--include='worker-*.yml' --exclude='*'` enforced. Idempotent;
    a no-op once the fleet has converged.

    This is the single documented exception to "report, never delete"
    (spec §7.4). Everything else stale is reported and left for a human.

    Args:
        protected: Router filenames to keep even if they match the legacy
            prefix. The edge passes every current deployment's filename so an
            app legitimately named `worker-*` is not deleted out from under it.

    Returns:
        The filenames removed, for the caller to log.
    """
    if not DYNAMIC.is_dir():
        return []
    protected = protected or set()
    reaped = []
    for p in sorted(DYNAMIC.glob(f"{_LEGACY_ROUTER_PREFIX}*.yml")):
        if p.name in protected:
            continue
        p.unlink()
        reaped.append(p.name)
    return reaped


@dataclass(frozen=True)
class RouteResult:
    """What one source's edge rendering wrote, and what the tenant allowlist refused."""

    rendered: list[str]
    refused: list[str]


def _render_routers(
    tree: Path, org: Org, *, tenant: str | None, domains: list[str] | None
) -> RouteResult:
    """On the edge: render a router for EVERY Deployment with ingress (spec §6).

    Cross-host router delivery is gone. The edge reads the same git tree every
    host reads and resolves each backend from the org manifest, so the app host
    authors nothing that reaches the edge (spec §6, §6.3).

    Stale routers for retired apps are NOT removed here — a manifest disappearing
    from git is destructive, and the loop reports rather than deletes (spec §7.4).
    The one bounded exception is the legacy `worker-` prefix (reap_legacy_worker_routers).

    Args:
        tree: Root of the manifest tree the loop pulled.
        org: The validated org manifest, source of every backend private IP.
        tenant: The source's tenant name, or None for the platform source.
        domains: The tenant allowlist (spec §4 anti-hijack). When set, an ingress
            whose host is in no allowed domain is REFUSED — recorded, never written.
            None (the platform source) writes every host.

    Returns:
        The router names written and the refusal lines (one per foreign host).
    """
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    deployments = load_deployments(tree)
    protected = {f"{m.metadata.name}.yml" for m in deployments}
    for stale in reap_legacy_worker_routers(protected):
        print(f"edge: reaped legacy router {stale} (cross-host delivery is retired)")
    facilities = load_facilities(tree)
    vocab = route_vocabulary(facilities)
    router_present = any(f.metadata.name == "router" for f in facilities)
    rendered: list[str] = []
    refused: list[str] = []
    for manifest in deployments:
        ingress = manifest.raw.get("spec", {}).get("ingress") or []
        if not ingress:
            continue
        # A deployment placed on an entry host runs ALONGSIDE Traefik, so
        # cmd_apply already rendered its router there with a container-name
        # backend. Re-rendering it from here would overwrite that working file
        # with a `privateIp:port` backend nothing is listening on.
        placement = manifest.spec.placement
        if placement is not None and placement.role in _ENTRY_ROLES:
            continue
        if domains is not None:
            allowed = []
            for ing in ingress:
                host = str(ing.get("host", ""))
                if host_in_domains(host, domains):
                    allowed.append(ing)
                else:
                    line = f"REFUSED route {host}: not in tenant {tenant} domains"
                    refused.append(line)
                    print(line, file=sys.stderr)
            if not allowed:
                continue
            ingress = allowed
        resolved = [
            {k: v for k, v in ing.items() if k not in {"service", "port", "hostPort"}}
            | {"address": backend_address(org, manifest, ing, router_present=router_present)}
            for ing in ingress
        ]
        name = manifest.metadata.name
        write_ingress(name, resolved, vocab)
        rendered.append(name)
    return RouteResult(rendered, refused)


def render_edge_routers(tree: Path, org: Org) -> list[str]:
    """The platform edge render: every host, no tenant allowlist. Returns the names written."""
    return _render_routers(tree, org, tenant=None, domains=None).rendered


def render_routes(ctx: TreeContext) -> RouteResult:
    """On the edge: render ONE source's routers, applying the tenant domain allowlist.

    The platform source (ctx.tenant is None) is unconstrained — it owns the platform
    domains. A tenant source may only route hosts in its own `domains` from the
    platform tenants.yml (spec §4 anti-hijack); a tenant missing from the registry, or
    a platform tree with no tenants.yml, gets an empty allowlist and routes nothing
    (fail-closed).
    """
    if ctx.org is None:
        return RouteResult([], [])
    domains: list[str] | None = None
    if ctx.tenant is not None:
        row = ctx.tenants.get(ctx.tenant) if ctx.tenants is not None else None
        domains = row.domains if row is not None else []
    return _render_routers(ctx.tree, ctx.org, tenant=ctx.tenant, domains=domains)


def facility_health(manifest: Facility) -> str | None:
    """Whether this facility's containers are actually up on THIS host.

    Vocabulary is git-derived and identical fleet-wide; health is same-host
    (spec §5.3). A facility declaring no containers has nothing to check — a
    pure route declaration like basic-auth is a statement about the edge's
    middleware file, not about a process.

    Args:
        manifest: The facility being applied.

    Returns:
        None when healthy, otherwise a one-line reason naming the container.
    """
    for container in manifest.spec.health.containers:
        exists, healthy = _container_state(container)
        if not exists:
            return f"container {container!r} is not running"
        if not healthy:
            return f"container {container!r} is running but not healthy"
    return None


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
    path = _db_env_path(app)
    return _read_env_file(path) if path.exists() else {}


def write_db_env(app: str, env: dict[str, str]) -> str:
    """Write an app's DB creds env-file (600, deploy-owned); return its path."""
    SECRETS.mkdir(parents=True, exist_ok=True)
    path = _db_env_path(app)
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


def load_db_seed() -> bytes | None:
    """Read NUK_DB_SEED from the converge-delivered seed file, or None if absent.

    Absent means a legacy single-host install: callers keep the random-password
    behavior so old deploys are byte-identical.
    """
    if not DB_SEED_ENV.exists():
        return None
    seed = _read_env_file(DB_SEED_ENV).get("NUK_DB_SEED")
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
        sys.exit(f"nuk: derive_db_password kind must be 'pg' or 'redis', got {kind!r}")
    info = f"nuk-db:{kind}:{app}".encode()
    # RFC 5869 HKDF-SHA-256, salt = HashLen zeros (i.e. empty salt), one block.
    prk = hmac.new(b"\x00" * 32, seed, hashlib.sha256).digest()
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(okm).rstrip(b"=").decode()


def _db_password(kind: str, app: str, prev_url: str | None) -> str:
    """Seed-derived when the fleet seed is present, else the previously issued one, else new."""
    seed = load_db_seed()
    if seed is not None:
        return derive_db_password(seed, kind, app)
    return _pw_from_url(prev_url) or secrets.token_urlsafe(24)


def _pg_driver(pg: object) -> str | None:
    """The driver from raw `spec.databases.postgres` (bare `true` has none)."""
    driver = pg.get("driver") if isinstance(pg, dict) else None
    return driver if isinstance(driver, str) else None


def _pg_url(app: str, pw: str, host: str, driver: str | None) -> str:
    """DATABASE_URL for an app's database; `driver` picks the SQLAlchemy scheme suffix."""
    scheme = f"postgresql+{driver}" if driver else "postgresql"
    return f"{scheme}://{app}:{pw}@{host}:5432/{app}"


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
        SystemExit: When `driver` is not a lowercase token.
    """
    if driver and not re.fullmatch(r"[a-z][a-z0-9]*", driver):
        sys.exit(f"nuk: invalid postgres driver {driver!r}")
    pw = _db_password("pg", app, prev_url)
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
    return _pg_url(app, pw, PG_CONTAINER, driver)


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
    return _redis_url(app, pw, REDIS_CONTAINER)


def data_host_ip(org: Org) -> str | None:
    """Return the privateIp of the org's `data` host, or None if undeclared."""
    host = org.host_for("data")
    return host.private_ip if host else None


def provision_databases(
    app: str, databases: dict, facilities: list[Facility], *, remote_ip: str | None = None
) -> str | None:
    """Provision the databases a manifest requested.

    Args:
        app: The app name.
        databases: The raw `spec.databases` dict.
        facilities: The tree's Facility manifests, to check the `databases`
            env capability is actually declared before binding against it.
        remote_ip: The data host's private IP when this host is NOT the data
            host; then this host only derives creds (spec §3.1). None means the
            local data stack is provisioned, exactly as before.

    Returns:
        The path to the creds env-file the override should inject, or None when
        no databases are requested.
    """
    pg = databases.get("postgres")
    want_pg = bool(pg)
    want_redis = bool(databases.get("redis"))
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
    if facilities and env_facility(facilities, _DATABASES_CAPABILITY) is None:
        sys.exit(
            f"{app}: spec.databases requests {_DATABASES_CAPABILITY!r} but no facility "
            f"provides it. Apply facilities/data-stack.yml first, or drop spec.databases."
        )
    _safe_ident(app)
    if remote_ip is not None:
        # The app host derives; it never provisions (spec §3.1 topology condition).
        seed = load_db_seed()
        if seed is None:
            sys.exit(
                f"{app}: spec.databases needs the fleet DB seed at {DB_SEED_ENV} "
                f"to derive remote credentials — deliver it via converge.sh"
            )
        env: dict[str, str] = {}  # remote mode derives fresh; never carry stale keys
        if want_pg:
            pw = derive_db_password(seed, "pg", app)
            env["DATABASE_URL"] = _pg_url(app, pw, remote_ip, _pg_driver(pg))
        if want_redis:
            env["REDIS_URL"] = _redis_url(app, derive_db_password(seed, "redis", app), remote_ip)
        return write_db_env(app, env)
    preflight_data_stack(want_pg, want_redis)
    prev = read_db_env(app)
    env = {}
    if want_pg:
        env["DATABASE_URL"] = ensure_postgres(app, prev.get("DATABASE_URL"), _pg_driver(pg))
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
    _db_env_path(app).unlink(missing_ok=True)


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
# target cannot meaningfully scan past a few dozen entries. Combined with the
# same-release refresh below, 20 is effectively "every recent release".
RELEASE_LIMIT = 20

# /var/lib/nuk is the loop's state dir (CONVERGE_STATE, Task 3). releases/ is
# created by cloud-init and install_converge (Task 7) and defensively here, so a
# hand-run `sudo nuk apply` on a pre-loop host still records (spec §8: survives
# VM rebuild by living on the host's data volume).
RELEASES = CONVERGE_STATE / "releases"


def _iso_utc_now() -> str:
    """Current time as an ISO-8601 UTC timestamp with a `Z` suffix."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _provenance_path(name: str) -> Path:
    """On-disk path of an app's provenance record."""
    return project_dir(name) / "provenance.json"


def _releases_path(name: str) -> Path:
    """On-disk path of an app's release history (spec §8)."""
    return RELEASES / f"{name}.jsonl"


def read_provenance_history(name: str) -> list[dict]:
    """Every recorded release for `name`, oldest first; `[]` if none.

    Reads /var/lib/nuk/releases/<name>.jsonl, skipping unparseable lines — a
    half-written line from a killed apply must not blank the history. When the
    JSONL does not exist yet, a legacy DEPLOYS/<name>/provenance.json (a bare
    object from nuk <= 0.18, or a list from the interim 0.19 format) seeds the
    history; the legacy file is never written. Reads have no side effects: the
    upgrade happens on the next append anyway.
    """
    path = _releases_path(name)
    if not path.exists():
        data = _read_json_safe(_provenance_path(name))
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        return []
    entries: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def read_provenance(name: str) -> dict | None:
    """The CURRENT release for `name`, or None if nothing is recorded.

    Signature and contract unchanged across the history migration: `cmd_status`
    and `_overview_provenance` want one entry, and "current" is the newest.
    """
    history = read_provenance_history(name)
    return history[-1] if history else None


def write_provenance(
    name: str, *, repo: str | None, branch: str, commit: str | None, image_digest: str | None
) -> None:
    """Append this release to /var/lib/nuk/releases/<name>.jsonl.

    Re-applying the SAME release (identical repo/branch/commit/digest) refreshes
    the existing entry's timestamp instead of appending. The loop applies every
    cycle whether or not anything changed, so appending unconditionally would
    grow the file by ~4 entries a day per app and shift every `rollback --to`
    index under the operator between one look and the next. The history records
    releases, not cycles. Keeps the last RELEASE_LIMIT entries (spec §8).

    Raises on write failure; the caller (`cmd_apply`) treats this as best-effort
    and must not fail the deploy over it.

    Args:
        name: The deployment name.
        repo: The declared source repo, if any.
        branch: The declared source branch.
        commit: The full deployed commit sha, if resolvable.
        image_digest: The deployed image's digest, if resolvable.
    """
    entry = {
        "repo": repo,
        "branch": branch,
        "commit": commit,
        "imageDigest": image_digest,
        "appliedAt": _iso_utc_now(),
    }
    history = read_provenance_history(name)
    identity = ("repo", "branch", "commit", "imageDigest")
    if history and all(history[-1].get(k) == entry[k] for k in identity):
        history[-1] = entry
    else:
        history.append(entry)
    RELEASES.mkdir(parents=True, exist_ok=True)
    _releases_path(name).write_text(
        "".join(json.dumps(e) + "\n" for e in history[-RELEASE_LIMIT:]),
        encoding="utf-8",
    )


def _full_commit_sha(repo_dir: Path) -> str | None:
    """Full HEAD sha of `repo_dir`'s checkout, or None if unavailable."""
    return _git_try(repo_dir, "rev-parse", "HEAD")


def _parse_compose_images_json(text: str) -> list[dict]:
    """Parse `docker compose images --format json` output (one array or JSON-lines)."""
    text = text.strip()
    if not text:
        return []
    try:
        if text.startswith("["):
            data = json.loads(text)
            rows = data if isinstance(data, list) else []
        else:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (ValueError, json.JSONDecodeError):
        return []
    return [row for row in rows if isinstance(row, dict)]


def _resolve_image_digest(name: str, raw: dict) -> str | None:
    """Best-effort digest of the app's first compose image, or None if unresolvable."""
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, raw), "images", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    rows = _parse_compose_images_json(proc.stdout)
    if not rows:
        return None
    repository = rows[0].get("Repository")
    if not repository:
        return None
    tag = rows[0].get("Tag") or "latest"
    try:
        digest = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", f"{repository}:{tag}"],  # noqa: S607  # docker on PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return digest or None


# --- status overview (nukview data-layer port) ---------------------------------
# Ported from nukview's server-only data layer (buildOverview/readApp/driftFor in
# nukview's $lib/server/nuk.ts) so the overview logic lives in ONE place; nukview
# becomes a thin renderer over this JSON. Field names mirror nukview's types.ts
# by key so the renderer needs no remap. Every field degrades on a missing
# source — this never throws out of build_overview().


def _read_yaml_safe(path: Path) -> dict | list | None:
    """Best-effort YAML read: None on any I/O or parse error, never raises."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None


def _read_json_safe(path: Path) -> object:
    """Best-effort JSON read: None on any I/O or parse error, never raises."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _git_provenance(repo_dir: Path) -> dict:
    """Full commit sha + committer date + github web URL for `repo_dir`'s HEAD.

    Returns {} when there is no checkout / no commit — the caller degrades that
    field rather than failing.
    """
    out = _git_try(repo_dir, "log", "-1", "--format=%H%x09%cI")
    if not out:
        return {}
    full_commit, _, date = out.partition("\t")
    return {
        "full_commit": full_commit,
        "last_commit": date or None,
        "repo_url": git_origin(str(repo_dir)),
    }


_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def _read_version(repo_dir: Path) -> str | None:
    """Best-effort app version: pyproject.toml > package.json > `git describe`.

    Mirrors nukview's readVersion — the controller checkout has no tags, so
    version files win; `git describe` is the floor and degrades to a short sha.
    """
    pyproject = repo_dir / "pyproject.toml"
    if pyproject.exists():
        m = _VERSION_RE.search(pyproject.read_text(encoding="utf-8"))
        if m:
            return m.group(1)
    data = _read_json_safe(repo_dir / "package.json")
    version = data.get("version") if isinstance(data, dict) else None
    if isinstance(version, str):
        return version
    return _git_try(repo_dir, "describe", "--tags", "--always", "--abbrev=7")


def _list_workflows(repo_dir: Path) -> list[dict]:
    """GitHub Actions workflows in `repo_dir`, with normalised trigger events."""
    wf_dir = repo_dir / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    out = []
    for f in sorted(wf_dir.iterdir()):
        if f.suffix not in {".yml", ".yaml"}:
            continue
        doc = _read_yaml_safe(f)
        doc = doc if isinstance(doc, dict) else {}
        # YAML 1.1 parses the bare key `on:` as the boolean True — PyYAML follows
        # that resolver, so a GitHub Actions workflow's trigger key lands under
        # `True`, not the string "on". Check both.
        on = doc.get("on", doc.get(True))
        if isinstance(on, str):
            triggers = [on]
        elif isinstance(on, list):
            triggers = on
        elif isinstance(on, dict):
            triggers = list(on.keys())
        else:
            triggers = []
        name = doc.get("name")
        wf_name = name if isinstance(name, str) else f.name
        out.append({"file": f.name, "name": wf_name, "triggers": triggers})
    return out


def _dynamic_routers(name: str) -> list[dict] | None:
    """Router id/rule pairs nuk rendered into the Traefik file provider for `name`."""
    doc = _read_yaml_safe(_router_file(name))
    http = doc.get("http") if isinstance(doc, dict) else None
    routers = http.get("routers") if isinstance(http, dict) else None
    if not routers:
        return None
    return [
        {"id": rid, "rule": (r or {}).get("rule", ""), "live": None} for rid, r in routers.items()
    ]


def _probe(host: str, timeout: float = 2.5) -> str | None:
    """Black-box "is it serving?" — outbound HTTPS HEAD, never Docker.

    Any HTTP answer (incl. 3xx/4xx) means Traefik routed to a live backend;
    >=500 means the backend is down / showing the maintenance page. An
    unreachable host (DNS, TLS, timeout, connection refused) is unknown (None),
    not "missing" — nuk cannot tell "no DNS" from "not my problem" from here.
    """
    req = urllib.request.Request(f"https://{host}/", method="HEAD")  # noqa: S310  # fixed https scheme
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # fixed https scheme
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    return "missing" if status >= 500 else "enabled"  # noqa: PLR2004  # HTTP status code, not a magic number


def _annotate_routers(routers: list[dict] | None, hosts: list[str]) -> list[dict]:
    """Attach a best-effort live probe to each router, matched by its rule's host."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        live_by_host = dict(zip(hosts, pool.map(_probe, hosts), strict=True))
    out = []
    for r in routers or []:
        host = next((h for h in hosts if f"`{h}`" in r.get("rule", "")), None)
        out.append({**r, "live": live_by_host.get(host) if host else None})
    return out


def _drift_for(hosts: list[str], routers: list[dict] | None) -> str:
    """Two-file consistency check between the manifest's hosts and Traefik's routers.

    Does every manifest ingress host appear in a router nuk actually rendered?
    Compares two files nuk itself wrote — never re-renders. Returns "unknown"
    when there are no hosts to check, "drift" when the dynamic file is missing
    or a host is absent from it, else "in-sync".
    """
    if not hosts:
        return "unknown"
    if routers is None:
        return "drift"
    blob = " ".join(r.get("rule", "") for r in routers)
    return "in-sync" if all(f"`{h}`" in blob for h in hosts) else "drift"


def _overview_ingress_fields(spec: dict) -> tuple[list[str], list[dict]]:
    """Deduped host list + full ingress view list from a manifest's `spec.ingress`."""
    entries = [i for i in (spec.get("ingress") or []) if isinstance(i, dict) and i.get("host")]
    hosts = list(dict.fromkeys(i["host"] for i in entries))
    ingress = [
        {
            "host": i["host"],
            "service": i.get("service"),
            "port": i.get("port"),
            "path": i.get("path"),
            "auth": i.get("auth"),
        }
        for i in entries
    ]
    return hosts, ingress


def _overview_features(spec: dict) -> dict:
    """`spec.databases` -> the declared-backing-services view."""
    databases = spec.get("databases")
    databases = databases if isinstance(databases, dict) else {}
    pg = databases.get("postgres")
    return {
        "postgres": bool(pg),
        "redis": bool(databases.get("redis")),
        "postgresDriver": _pg_driver(pg),
    }


def _overview_provenance(
    name: str, source_raw: dict | None
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """commit/commitUrl/repoUrl/lastCommit/imageDigest, provenance.json-first.

    Returns:
        (commit, commit_url, repo_url, last_commit, image_digest) — each None
        when its source is unavailable.
    """
    repo_dir = _repo_dir(name)
    provenance = read_provenance(name)
    git_prov = _git_provenance(repo_dir)

    full_commit = (provenance or {}).get("commit") or git_prov.get("full_commit")
    commit = full_commit[:12] if full_commit else None

    web = git_prov.get("repo_url")
    commit_url = f"{web}/commit/{full_commit}" if web and full_commit else None
    declared_repo_url = (
        github_url(source_raw["repo"]) if source_raw and source_raw.get("repo") else None
    )
    return (
        commit,
        commit_url,
        declared_repo_url or web,
        git_prov.get("last_commit"),
        (provenance or {}).get("imageDigest"),
    )


def _read_app_overview(name: str, *, probe_enabled: bool = False) -> dict:
    """Build one app's Overview entry from on-disk state. Degrades; never raises."""
    notes: list[str] = []
    manifest_raw = _read_yaml_safe(_manifest_file(name))
    if manifest_raw is None:
        notes.append("manifest.yml unreadable")
    spec = manifest_raw.get("spec") if isinstance(manifest_raw, dict) else None
    spec = spec if isinstance(spec, dict) else {}

    hosts, ingress = _overview_ingress_fields(spec)
    source_raw = spec.get("source") if isinstance(spec.get("source"), dict) else None
    source = (
        {"repo": source_raw.get("repo"), "branch": source_raw.get("branch")} if source_raw else None
    )

    commit, commit_url, repo_url, last_commit, image_digest = _overview_provenance(name, source_raw)
    if not commit:
        notes.append("no git checkout / commit unavailable")

    repo_dir = _repo_dir(name)
    routers = _dynamic_routers(name)
    routers_out = _annotate_routers(routers, hosts) if probe_enabled else (routers or [])

    return {
        "name": name,
        "hosts": hosts,
        "source": source,
        "repoUrl": repo_url,
        "commit": commit,
        "commitUrl": commit_url,
        "lastCommit": last_commit,
        "version": _read_version(repo_dir),
        "routers": routers_out,
        "drift": _drift_for(hosts, routers),
        "features": _overview_features(spec),
        "workflows": _list_workflows(repo_dir),
        "ingress": ingress,
        "notes": notes,
        "imageDigest": image_digest,
    }


def build_overview(*, probe_enabled: bool = False) -> dict:
    """Walk DEPLOYS/*/ and build the org-wide status Overview. Degrades; never raises."""
    errors: list[str] = []
    names: list[str] = []
    if DEPLOYS.exists():
        names = sorted(p.name for p in DEPLOYS.iterdir() if p.is_dir())
    else:
        errors.append(f"cannot read {DEPLOYS} — is /opt/nuklaut mounted?")
    return {
        "apps": [_read_app_overview(n, probe_enabled=probe_enabled) for n in names],
        "liveRoutingAvailable": False,  # Traefik api@internal integration is a later chapter
        "nukRoot": str(ROOT),
        "generatedAt": _iso_utc_now(),
        "errors": errors,
    }


def _soll_vs_ist(overview: dict, org_file: Path | None) -> dict:
    """`--all`: declared org hosts (soll) vs this command's local observation (ist).

    Args:
        overview: The already-built Overview dict (read for its observed app count).
        org_file: Path to the org manifest (`nuklaut.org.yml`); required.

    Returns:
        The extra top-level keys `status --all` adds to the Overview.

    Raises:
        SystemExit: When `org_file` is not given, or is not a valid Org manifest.
    """
    if org_file is None:
        sys.exit("nuk status --all: --org-file PATH is required (path to nuklaut.org.yml)")
    org = load_org(org_file)
    return {
        "hosts": [h.model_dump(by_alias=True) for h in org.hosts],
        "sollVsIst": {
            "declaredHosts": len(org.hosts),
            # TODO(K2.5): per-host observed via DOCKER_HOST fan-out (ssh per host,  # noqa: FIX002
            # one nuk status per host, merge). Kapitel 1 is single-host, so
            # "observed" is just this controller — the one this command runs on.
            "observedHosts": 1,
            "declaredApps": None,  # nukorg/v1 does not declare apps (yet)
            "observedApps": len(overview["apps"]),
        },
    }


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
    raw = manifest.raw
    name = manifest.metadata.name
    raw_spec = raw.get("spec") or {}
    if manifest.kind == "Facility" and not _is_privileged():
        print(
            f"{name}: Facility apply requires root or membership in group "
            f"{_FACILITY_GROUP!r} (spec §4.4). Refusing."
        )
        sys.exit(1)
    ctx = ctx or TreeContext.for_path(manifest_path)
    role, self_ip = ctx.role, ctx.self_ip
    if not placement_matches(manifest, role):
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
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    DEPLOYS.mkdir(parents=True, exist_ok=True)
    source = manifest.spec.source
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
        and not raw_spec.get("compose")
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
    elif manifest.kind == "Facility":
        # A sourceless Facility (data-stack, ingress): its compose payload ships
        # beside its manifest at <tree>/facilities/<name>/ — the manifest's own
        # directory is the tree root for a hand-run apply, the loop passes the
        # archive root. Mirror it into the project dir exactly like a cloned
        # repo, so compose_args' existing `-f repo/<file>` resolution works
        # unchanged.
        payload = manifest_path.resolve().parent / name
        if not payload.is_dir():
            sys.exit(
                f"{manifest_path}: Facility {name} has no source.repo and no "
                f"facilities/{name}/ payload directory — nothing to apply"
            )
        shutil.rmtree(repo, ignore_errors=True)
        sh("rsync", "-a", "--delete", f"{payload}/", str(repo) + "/")
    else:
        sys.exit(f"{manifest_path}: spec.source.repo is required unless --repo-path is given")
    if pin_digest:
        _pin_image(name, raw, pin_digest)
    ingress = raw_spec.get("ingress", []) or []
    org = ctx.org
    remote_ip = None
    if org is not None:
        # The remote decision mirrors provision_remote_databases's owner gate
        # exactly (spec §3.1): this host provisions locally iff it owns the
        # `databases` capability. Keying on `role != "data"` diverges for an
        # all-in-one host, which placement_matches treats as owner of every
        # facility — the two sides must never disagree.
        owner = env_facility(facilities, _DATABASES_CAPABILITY)
        owns_databases = owner is not None and placement_matches(owner, role)
        if not owns_databases:
            remote_ip = data_host_ip(org)
    db_env = provision_databases(
        name, raw_spec.get("databases") or {}, facilities, remote_ip=remote_ip
    )
    db_services = resolve_db_services(name, raw, db_env)
    if db_env and not db_services:
        print(
            f"{name}: databases provisioned but no service to attach them to — "
            f"DATABASE_URL/REDIS_URL won't be injected. Add an ingress entry, or set "
            f"spec.databases.attachTo / attachAll to target a worker."
        )
    env_from = resolve_env_from(raw_spec)
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
        sys.exit(
            f"{name}: host is non-edge (role={role}) but /etc/nuklaut/host.env has no "
            f"PRIVATE_IP — cannot publish ingress for the edge to reach"
        )
    write_override(
        name,
        ingress,
        db_env,
        env_from,
        db_services,
        publish_ip=self_ip if edge_term else None,
        local_data=remote_ip is None,
    )
    strategy = manifest.spec.strategy
    if strategy is not None and strategy.type == "blue-green":
        # Blue-green replaces "ingress -> up -d" with a colour rollout: bring the
        # idle colour up (its compose profile), gate on its health, flip the
        # app-host file router to it, record it, then drain the old colour. The
        # app host owns its own router here (the edge routes stably to it), so
        # the colourless `edge_term` unlink below is deliberately bypassed.
        persist_manifest(raw, manifest_path, pdir / "manifest.yml", repo_path)
        _apply_blue_green(name, raw, ingress, vocab, strategy)
    else:
        if edge_term:
            _router_file(name).unlink(missing_ok=True)  # inert here; the edge owns it
        else:
            write_ingress(name, ingress, vocab)
        persist_manifest(raw, manifest_path, pdir / "manifest.yml", repo_path)
        # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
        # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
        # whose image id changed. A declaration-only Facility has no compose file at
        # all — there is nothing to bring up.
        if not declaration_only:
            sh(*compose_args(name, raw), "up", "-d")
    # An unhealthy facility must not become "current": write_provenance is what
    # `nuk status`, `nuk rollback` and drift.sh read as the deployed state, so
    # appending here would both hide the breakage and put the last known-good
    # entry out of rollback's reach (spec §5.4).
    if manifest.kind == "Facility" and (reason := facility_health(manifest)) is not None:
        sys.exit(f"{name}: facility is not healthy — {reason}. Provenance not appended.")
    # Provenance is best-effort: `status` prefers it over the live repo/ checkout
    # (trustworthy even for rsync-mirrored, .git-less workflow deploys), but a
    # write failure here must never fail an otherwise-successful apply.
    try:
        write_provenance(
            name,
            repo=source.repo,
            branch=source.branch,
            commit=_full_commit_sha(repo) if (repo / ".git").exists() else None,
            image_digest=_resolve_image_digest(name, raw),
        )
    except OSError as e:
        print(f"{name}: provenance not recorded ({e})")


def _apply_blue_green(
    name: str,
    raw: dict,
    ingress: list[dict],
    vocab: dict[str, list[str]],
    strategy: Strategy,
) -> None:
    """Roll a blue-green deployment onto the idle colour.

    Brings the idle colour's compose profile up, gates on the strategy's health
    probe, flips the app-host file router to that colour, records it as active,
    and drains the previous colour — unless `keepPrevious` keeps it for an
    instant rollback.

    Args:
        name: The deployment name.
        raw: The raw manifest dict (for `compose_args`).
        ingress: The raw `spec.ingress[]` entries.
        vocab: Route capabilities resolved from the tree.
        strategy: The parsed `spec.strategy` block.
    """
    active = active_colour(name)
    idle = idle_colour(active)
    health = strategy.health
    sh(*compose_args(name, raw), "--profile", idle, "up", "-d")
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
    write_ingress(name, ingress, vocab, colour=idle)
    record_active_colour(name, idle)
    if not strategy.keep_previous:
        # Drain every service the deployment publishes — the probe service plus
        # each ingress backend — so a manifest that names them other than the
        # conventional backend/frontend still tears the old colour fully down.
        # dict.fromkeys dedups while preserving manifest order.
        published = dict.fromkeys(
            [health.service, *(i.get("service") for i in ingress if i.get("service"))]
        )
        sh(
            *compose_args(name, raw),
            "--profile",
            active,
            "down",
            *(f"{service}-{active}" for service in published),
        )


def _rollback_blue_green(
    name: str,
    raw: dict,
    ingress: list[dict],
    vocab: dict[str, list[str]],
    strategy: Strategy,
) -> None:
    """Flip a blue-green deployment's router back to its previous colour.

    The inverse of `_apply_blue_green`: the previous colour is the idle one, so
    bring its compose profile back up (a no-op when `keepPrevious` kept it, and
    the restart when the last apply drained it), gate on the same health probe,
    flip the app-host file router back to it, and record it as active. No image
    change is needed — the previous colour's bits are still on the host.
    """
    previous = idle_colour(active_colour(name))
    health = strategy.health
    sh(*compose_args(name, raw), "--profile", previous, "up", "-d")
    await_healthy(
        _container_name(name, health.service, previous),
        health.path,
        timeout=health.timeout,
        interval=health.interval,
        port=health.port or 8000,
        exec_=sh,
    )
    write_ingress(name, ingress, vocab, colour=previous)
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
        sys.exit(f"nuk: {name}: no such deployment ({manifest_file} not found)")
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
    if converge:
        overview["converge"] = converge
    if show_all:
        overview.update(_soll_vs_ist(overview, org_file))
    print(json.dumps(overview, indent=2 if pretty else None))


def cmd_logs(name: str) -> None:
    """Follow compose logs for a deployment."""
    manifest = load(_manifest_file(name))
    sh(*compose_args(name, manifest.raw), "logs", "-f")


def cmd_rollout(name: str) -> None:
    """Git pull + compose pull + up -d for a deployment."""
    manifest = load(_manifest_file(name))
    repo = _repo_dir(name)
    if (repo / ".git").exists():
        sh("git", "-C", str(repo), "pull", "--ff-only")
    # else: workflow-managed deployment — re-trigger the workflow to update the tree.
    sh(*compose_args(name, manifest.raw), "pull")
    sh(*compose_args(name, manifest.raw), "up", "-d")


def _compose_images(name: str, raw: dict) -> list[str]:
    """The image references the compose project resolves to, in service order."""
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, raw), "config", "--images"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _pin_image(name: str, raw: dict, pin_digest: str) -> None:
    """Point the app's compose image reference at the pinned digest (spec §8).

    The digest is the identity of the re-applied release. Order matters:
    resolve the retag targets from the (already detached) compose tree first,
    then `docker pull` the digest — the pull IS the preflight, and its failure
    aborts before anything is written or recreated, leaving the current state
    running. The runner's pre-pull model (cmd_apply's "No --pull here") already treats the
    daemon's tags as shared mutable state; this is the same move in the
    opposite direction.

    Raises:
        SystemExit: If no compose image comes from the digest's repository, or
            the pull fails.
    """
    repo_name = pin_digest.split("@", maxsplit=1)[0]
    refs = [
        ref for ref in _compose_images(name, raw) if ref.split("@")[0].split(":")[0] == repo_name
    ]
    if not refs:
        sys.exit(
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
        SystemExit: If there is nothing to roll back to, the index is out of
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
            commit = (entry.get("commit") or "-")[:12]
            digest = (entry.get("imageDigest") or "-").split("@")[-1][:12]
            marker = "  (current)" if i == len(history) - 1 else ""
            print(f"{i:>3}  {commit}  {digest}  {entry.get('appliedAt', '?')}{marker}")
        return
    manifest = _manifest_file(name)
    if not manifest.exists():
        sys.exit(f"{name}: {manifest} is missing — nothing to re-apply")
    try:
        raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        parsed = _MANIFEST_ADAPTER.validate_python(raw)
    except ValidationError as e:
        sys.exit(
            f"{name}: the persisted manifest no longer validates under the current "
            f"schema (a field was removed since; spec §8) — refusing to silently "
            f"upgrade it into the new schema: {e}"
        )
    if parsed.kind != "Deployment":
        sys.exit(
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
            sys.exit(f"{name}: no previous release recorded — nothing to roll back to")
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
        ingress = (raw.get("spec") or {}).get("ingress", []) or []
        _rollback_blue_green(name, raw, ingress, vocab, strategy)
        return
    if to is None and len(history) < 2:  # noqa: PLR2004  # need a current AND a previous
        sys.exit(f"{name}: no previous release recorded — nothing to roll back to")
    index = -2 if to is None else to
    try:
        entry = history[index]
    except IndexError:
        sys.exit(f"{name}: no release at index {to} (history has {len(history)} entries)")
    digest = entry.get("imageDigest")
    if not digest:
        sys.exit(
            f"{name}: the release at index {index} has no recorded imageDigest "
            f"(a source-built deploy, or one predating digest resolution) — it cannot "
            f"be re-applied by digest (spec §8). Roll forward, or re-apply its commit by hand."
        )
    commit = entry.get("commit")
    if not commit:
        sys.exit(
            f"{name}: the release at index {index} has no recorded commit "
            f"(a workflow deploy from a .git-less tree) — its compose tree is "
            f"unreproducible, cannot re-apply it"
        )
    print(f"{name}: rolling back to {digest} (applied {entry.get('appliedAt', '?')})")
    cmd_apply(manifest, None, pin_commit=commit, pin_digest=digest)


def cmd_delete(name: str, purge: bool) -> None:
    """Tear down a deployment, keeping its database unless `purge` is set."""
    pdir = project_dir(name)
    if (pdir / "manifest.yml").exists():
        manifest = load(pdir / "manifest.yml")
        subprocess.run([*compose_args(name, manifest.raw), "down", "-v"], check=False)  # noqa: S603  # argv built from fixed verbs
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
    if not DEPLOYS.exists():
        return []
    return sorted(p.name for p in DEPLOYS.iterdir() if p.is_dir() and (p / "manifest.yml").exists())


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
    ] = SOURCES_FILE,
    signers_dir: Annotated[
        Path, typer.Option("--signers-dir", help="allowed_signers.d: one trust file per source")
    ] = SIGNERS_DIR,
    state_dir: Annotated[
        Path, typer.Option("--state-dir", help="lock, per-source state, status file")
    ] = CONVERGE_STATE,
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
