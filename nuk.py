#!/usr/bin/env python3
"""nuk — minimal Kubernetes-shaped Docker Compose deployer.

Manifest (apiVersion: nuk/v1, kind: Deployment) describes one git repo with a
compose project, optional ingress hosts, and env files. State lives entirely in
/opt/nuklaut/ on the host; no daemon, no database.
"""

from __future__ import annotations

import grp
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
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
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

__version__ = "0.24.0"  # bumped on release by .github/workflows/release.yml

ROOT = Path("/opt/nuklaut")
DEPLOYS = ROOT / "deployments"
DYNAMIC = ROOT / "traefik" / "dynamic"
SECRETS = ROOT / "secrets"
# This host's identity, written world-readable (no secrets) by cloud-init. Absent on a
# legacy single-host controller -> read_self() defaults to an entry role (byte-identical).
HOST_ENV = Path("/etc/nuklaut/host.env")

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
    # Which gate to put in front of this route — NOT which implementation provides it.
    # `oauth` resolves to whatever `facilities.auth` selected for the org, because every
    # global.<impl>.yml deliberately defines the same middleware names (oauth-auth,
    # oauth-errors). So an org on Authentik still writes `auth: oauth` here.
    #
    # ⚠ This MUST stay a closed set. It was a bare `str | None`, and build_ingress matches
    #   it with if/elif and no else — so any unrecognised value rendered a router with NO
    #   auth middleware and NO error. `auth: authentik` is the tempting way to write it
    #   (it IS legal one layer up, in facilities.auth) and it silently published the route.
    #   An authentication control that fails OPEN on a typo is exactly the silent-failure
    #   class the 2026-07-21 rebuild exists to make structurally impossible.
    auth: Literal["basic", "oauth"] | None = None

    @field_validator("auth", mode="before")
    @classmethod
    def _reject_impl_names(cls, v: object) -> object:
        """Point the implementation names at the capability name they belong to.

        Raises:
            ValueError: If `auth` names an auth *implementation* rather than the gate.
        """
        if isinstance(v, str) and v in {"authentik", "oauth2-proxy"}:
            msg = (
                f"ingress.auth={v!r} names an auth IMPLEMENTATION, which belongs in the "
                f"org's facilities.auth. Per-route, write `auth: oauth` — it resolves to "
                f"whichever implementation this org runs."
            )
            raise ValueError(msg)
        return v

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


class Placement(BaseModel):
    """`spec.placement` — the role whose hosts run this manifest's containers.

    Shared by both kinds (spec §4.2). Replaces the two implicit placement
    mechanisms it supersedes: "whichever host someone ran `nuk apply` on", and
    converge.sh's `APPS="a.yml b.yml"` environment variable.
    """

    role: Literal["edge", "data", "app", "hypervisor", "all-in-one"]


class Health(_NullTolerant):
    """`spec.health` — how a facility proves it is actually up.

    Vocabulary is git-derived and fleet-wide; health is same-host (spec §5.3).
    Only the host whose `placement.role` owns a facility can check it.
    """

    containers: list[str] = []


class RouteProvide(BaseModel):
    """`spec.provides.route` — a stateless decoration a router can opt into.

    `capability` is what the facility HANDS OUT; a Deployment consumes it via
    the §5.3 field→capability map (`ingress[].auth: oauth` → `auth`).
    `middlewares` are applied in declaration order, outer→inner.
    """

    capability: str
    middlewares: list[str] = []


class EnvProvide(BaseModel):
    """`spec.provides.env` — a stateful binding handed to an app as env vars."""

    capability: str
    bind: Literal["postgres"]


class Provides(_NullTolerant):
    """`spec.provides` — what a Facility hands out.

    The whole of `Facility ≡ Deployment + spec.provides`.
    """

    route: RouteProvide | None = None
    env: EnvProvide | None = None


class Spec(_NullTolerant):
    """The manifest `spec` block."""

    model_config = ConfigDict(populate_by_name=True)

    source: Source = Source()
    compose: Compose = Compose()
    ingress: list[Ingress] = []
    env_from: list[EnvFrom] = Field(default=[], alias="envFrom")
    databases: Databases = Databases()
    placement: Placement | None = None


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
    role: Literal["edge", "data", "app", "hypervisor", "all-in-one"]
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


def build_override(  # noqa: C901, PLR0913, PLR0914, PLR0917  # frozen wire-contract API; one render pass
    name: str,  # noqa: ARG001  # kept for signature stability (frozen wire-contract API / tests)
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
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
                host_port = ing.get("hostPort") or port
                mapping = f"{publish_ip}:{host_port}:{port}"
                publish_ports.setdefault(svc, [])
                if mapping not in publish_ports[svc]:
                    publish_ports[svc].append(mapping)
    services: dict = {}
    for svc_name in ordered:
        is_ingress = svc_name in ingress_services
        is_db = svc_name in db_set
        # Publishing on a private IP replaces the (inert) local `edge` join.
        nets = (["edge"] if is_ingress and not publish_ip else []) + (["data"] if is_db else [])
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
    if any(s in db_set for s in services):
        networks["data"] = {"external": True}
    return {"services": services, "networks": networks}


def write_override(  # noqa: PLR0913, PLR0917  # thin writer over build_override's frozen API
    name: str,
    ingress: list[dict],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
) -> None:
    """Render and write `compose.override.yml` for an app (no-op when empty)."""
    doc = build_override(name, ingress, db_env, env_from, db_services, publish_ip)
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


# The gates the pre-facility code hardcoded. Retained for the legacy all-in-one
# path — a single-host controller with no facilities dir — so its renders stay
# byte-identical (spec §12). A tree that ships facilities/ overrides it entirely;
# test_shipped_facilities_reproduce_the_default_vocabulary keeps the two in step.
# Keys are CAPABILITY names (post-translation, see _ROUTE_CAPABILITY below).
DEFAULT_ROUTE_VOCAB: dict[str, list[str]] = {
    "auth": ["oauth-errors@file", "oauth-auth@file"],
    "basic": ["auth@file"],
}

# The §5.3 field→capability map for route effects: `ingress[].auth: oauth`
# consumes route capability `auth`. Field values absent here translate to
# themselves (`basic` → `basic`). Adding a capability adds a row.
_ROUTE_CAPABILITY: dict[str, str] = {"oauth": "auth"}


def build_ingress(  # noqa: C901, PLR0912  # one router-build loop; clean extraction would obscure the per-field ordering
    name: str, ingress: list[dict], vocab: dict[str, list[str]]
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
      auth        "oauth" -> gate via the oauth2-proxy GitHub forwardAuth chain
                  (needs an oauth2-proxy /oauth2/ route for <host>)
                  "basic" -> HTTP Basic Auth (auth@file middleware from global.yml)

    Args:
        name: The deployment name, used to prefix router/service ids.
        ingress: The raw `spec.ingress[]` entries.
        vocab: Route capabilities declared by the facilities in the git tree,
            mapped to their middleware chains (see route_vocabulary). A router
            that asks for a capability absent from this mapping is refused.

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
        # ⚠ The refusals below are load-bearing. The chain this replaced once had no
        #   `else`, and an unrecognised value fell through to a router with no auth
        #   middleware and no error — a security control failing OPEN. The lookup
        #   keeps that closed and widens it: an undeclared capability, and a
        #   capability whose chain is empty, are BOTH refusals (spec §5.4).
        want = ing.get("auth")
        if want is not None:
            # §5.3's field→capability map: the router asks for `oauth`, the
            # facility provides `auth`. Identity for unmapped values (`basic`).
            capability = _ROUTE_CAPABILITY.get(want, want)
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
        mw.append("maintenance-errors@file")
        router["middlewares"] = mw
        if "priority" in ing:
            router["priority"] = ing["priority"]
        routers[rid] = router
        # `address` (remote host:port) bypasses the local edge-network container
        # naming convention entirely — used for backends on another host (e.g. a
        # libvirt VM reached over the private vswitch/cloud-network).
        backend = (
            ing["address"] if ing.get("address") else f"{name}-{ing['service']}-1:{ing['port']}"
        )
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
                "entryPoints": ["websecure"],
                "service": rid,
                "middlewares": [rdid],
                "tls": {"certResolver": "letsencrypt"},
            }
    http = {"routers": routers, "services": services}
    if middlewares:
        http["middlewares"] = middlewares
    return {"http": http}


def write_ingress(name: str, ingress: list[dict], vocab: dict[str, list[str]]) -> None:
    """Render and write the Traefik dynamic file for an app (removes it if empty)."""
    target = DYNAMIC / f"{name}.yml"
    doc = build_ingress(name, ingress, vocab)
    if doc is None:
        target.unlink(missing_ok=True)
        return
    target.write_text(yaml.safe_dump(doc))


def read_self() -> tuple[str, str | None]:
    """Return (role, private_ip) for THIS host from /etc/nuklaut/host.env.

    cloud-init writes ROLE + PRIVATE_IP there (world-readable, no secrets). When
    the file is absent or unparseable — a legacy single-host controller — this
    returns ("all-in-one", None): an entry role, so apply keeps writing ingress
    locally and every existing render stays byte-identical.
    """
    role, private_ip = "all-in-one", None
    try:
        for raw_line in HOST_ENV.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("ROLE="):
                role = line[len("ROLE=") :].strip() or role
            elif line.startswith("PRIVATE_IP="):
                private_ip = line[len("PRIVATE_IP=") :].strip() or None
    except OSError:
        pass
    return role, private_ip


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


def load_facilities(tree: Path) -> list[Facility]:
    """Load every `kind: Facility` manifest in `<tree>/facilities/*.yml`.

    A tree with no facilities dir yields no facilities — the empty vocabulary.
    That is not an error here; it becomes one at lookup time, when a router asks
    for a capability nobody declared (spec §5.4).

    Args:
        tree: Root of the manifest tree (the git checkout the loop pulled).

    Returns:
        The facilities, ordered by filename for a deterministic vocabulary.
    """
    fdir = tree / FACILITY_DIR
    if not fdir.is_dir():
        return []
    return [m for p in sorted(fdir.glob("*.yml")) if isinstance(m := load(p), Facility)]


def route_vocabulary(facilities: list[Facility]) -> dict[str, list[str]]:
    """Map each declared route capability to its middleware chain.

    Order within a chain is the facility's declaration order: outer→inner, the
    same order the existing hardcoded chain uses (`[oauth-errors, oauth-auth]` —
    errors outside catches the 401-403 auth returns and serves the sign-in page).

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
# "whichever host someone ran `nuk apply` on", or converge.sh's APPS= variable.
DEPLOYMENT_DIR = "deployments"


def load_deployments(tree: Path) -> list[Deployment]:
    """Load every `kind: Deployment` manifest in `<tree>/deployments/*.yml`."""
    ddir = tree / DEPLOYMENT_DIR
    if not ddir.is_dir():
        return []
    return [m for p in sorted(ddir.glob("*.yml")) if isinstance(m := load(p), Deployment)]


def backend_address(org: Org, manifest: Deployment, ing: dict) -> str:
    """Where the edge should send traffic for one ingress entry.

    An explicit `address` (a backend the org does not manage) passes through.
    Otherwise the backend is the private IP of the org's host for this
    deployment's `placement.role`, on the published port — the port
    build_override publishes, which is `hostPort` when set and `port` otherwise.

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
    hosts = [h for h in org.hosts if h.role == placement.role]
    if not hosts:
        msg = (
            f"{manifest.metadata.name}: placement.role={placement.role!r} but the org "
            f"manifest declares no host with role {placement.role!r}."
        )
        raise ValueError(msg)
    return f"{hosts[0].private_ip}:{ing.get('hostPort') or ing['port']}"


# The prefix the deleted delivery path used to scope its rsync --delete. Files
# carrying it are the only thing this codebase ever removes without being asked:
# a stale worker-<name>.yml and a freshly-rendered <name>.yml define the SAME
# router key (ids are f"{name}-{i}"), Traefik picks between them
# nondeterministically, and a stale file predating an `auth:` addition could win.
_LEGACY_ROUTER_PREFIX = "worker-"


def reap_legacy_worker_routers() -> list[str]:
    """Remove routers the retired cross-host delivery path left on the edge.

    Bounded and one-time: scoped to the `worker-` prefix, so the edge's native
    routers (global.yml, oauth.yml, maintenance) are untouched — the same scope
    converge.sh's `--include='worker-*.yml' --exclude='*'` enforced. Idempotent;
    a no-op once the fleet has converged.

    This is the single documented exception to "report, never delete"
    (spec §7.4). Everything else stale is reported and left for a human.

    Returns:
        The filenames removed, for the caller to log.
    """
    if not DYNAMIC.is_dir():
        return []
    reaped = []
    for p in sorted(DYNAMIC.glob(f"{_LEGACY_ROUTER_PREFIX}*.yml")):
        p.unlink()
        reaped.append(p.name)
    return reaped


def render_edge_routers(tree: Path, org: Org) -> list[str]:
    """On the edge: render a router for EVERY Deployment with ingress.

    Cross-host router delivery is gone. The edge reads the same git tree every
    host reads and resolves each backend from the org manifest, so the app host
    authors nothing that reaches the edge (spec §6, §6.3).

    Stale routers for retired apps are NOT removed here — a manifest disappearing
    from git is destructive, and the loop reports rather than deletes (spec §7.4).
    The one bounded exception is the legacy `worker-` prefix (reap_legacy_worker_routers).

    Args:
        tree: Root of the manifest tree the loop pulled.
        org: The validated org manifest, source of every backend private IP.

    Returns:
        The names of the deployments whose routers were written.
    """
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    for stale in reap_legacy_worker_routers():
        print(f"edge: reaped legacy router {stale} (cross-host delivery is retired)")
    vocab = route_vocabulary(load_facilities(tree))
    rendered: list[str] = []
    for manifest in load_deployments(tree):
        ingress = manifest.raw.get("spec", {}).get("ingress") or []
        if not ingress:
            continue
        resolved = [
            {k: v for k, v in ing.items() if k not in {"service", "port", "hostPort"}}
            | {"address": backend_address(org, manifest, ing)}
            for ing in ingress
        ]
        name = manifest.metadata.name
        doc = build_ingress(name, resolved, vocab)
        if doc is None:
            continue
        (DYNAMIC / f"{name}.yml").write_text(yaml.safe_dump(doc))
        rendered.append(name)
    return rendered


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
    | `ingress[].auth: oauth` | route capability `auth`    |
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
    if any(ing.auth == "oauth" for ing in manifest.spec.ingress):
        caps.add("auth")
    db = manifest.spec.databases
    if db.postgres or db.redis:
        caps.add("databases")
    return caps


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


def provision_databases(app: str, databases: dict, facilities: list[Facility]) -> str | None:
    """Provision the databases a manifest requested.

    Args:
        app: The app name.
        databases: The raw `spec.databases` dict.
        facilities: The tree's Facility manifests, to check the `databases`
            env capability is actually declared before binding against it.

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
    if env_facility(facilities, _DATABASES_CAPABILITY) is None:
        sys.exit(
            f"{app}: spec.databases requests {_DATABASES_CAPABILITY!r} but no facility "
            f"provides it. Apply facilities/data-stack.yml first, or drop spec.databases."
        )
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


# --- provenance-on-apply -------------------------------------------------------
# `nuk apply` stamps DEPLOYS/<name>/provenance.json with the exact commit/image
# it deployed, so `status` has a trustworthy source even for rsync-mirrored
# (.git-less) workflow deploys. Best-effort by design: see the try/except around
# its only call site in cmd_apply.


def _iso_utc_now() -> str:
    """Current time as an ISO-8601 UTC timestamp with a `Z` suffix."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _provenance_path(name: str) -> Path:
    """On-disk path of an app's provenance record."""
    return project_dir(name) / "provenance.json"


def read_provenance(name: str) -> dict | None:
    """Read an app's provenance.json, or None if absent/unreadable/malformed."""
    path = _provenance_path(name)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_provenance(
    name: str, *, repo: str | None, branch: str, commit: str | None, image_digest: str | None
) -> None:
    """Write DEPLOYS/<name>/provenance.json — the trustworthy source `status` prefers.

    Raises on write failure; the caller (`cmd_apply`) treats this as best-effort
    and must not fail the deploy over it.

    Args:
        name: The deployment name.
        repo: The declared source repo, if any.
        branch: The declared source branch.
        commit: The full deployed commit sha, if resolvable.
        image_digest: The deployed image's digest, if resolvable.
    """
    payload = {
        "repo": repo,
        "branch": branch,
        "commit": commit,
        "imageDigest": image_digest,
        "appliedAt": _iso_utc_now(),
    }
    _provenance_path(name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _full_commit_sha(repo_dir: Path) -> str | None:
    """Full HEAD sha of `repo_dir`'s checkout, or None if unavailable."""
    try:
        out = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],  # noqa: S607  # git on PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=4,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return out or None


def _parse_compose_images_json(text: str) -> list[dict]:
    """Parse `docker compose images --format json` output (one array or JSON-lines)."""
    text = text.strip()
    if not text:
        return []
    try:
        if text.startswith("["):
            data = json.loads(text)
            return data if isinstance(data, list) else []
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    except (ValueError, json.JSONDecodeError):
        return []


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


def _git_provenance(repo_dir: Path) -> dict:
    """Full commit sha + committer date + github web URL for `repo_dir`'s HEAD.

    Returns {} when there is no checkout / no commit — the caller degrades that
    field rather than failing.
    """
    try:
        out = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["git", "-C", str(repo_dir), "log", "-1", "--format=%H%x09%cI"],  # noqa: S607  # git on PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=4,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return {}
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
    package_json = repo_dir / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        version = data.get("version") if isinstance(data, dict) else None
        if isinstance(version, str):
            return version
    try:
        out = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["git", "-C", str(repo_dir), "describe", "--tags", "--always", "--abbrev=7"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=4,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return out or None


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
    doc = _read_yaml_safe(DYNAMIC / f"{name}.yml")
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
    live_by_host = {h: _probe(h) for h in hosts}
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
        "postgresDriver": pg.get("driver") if isinstance(pg, dict) else None,
    }


def _overview_provenance(
    name: str, source_raw: dict | None
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """commit/commitUrl/repoUrl/lastCommit/imageDigest, provenance.json-first.

    Returns:
        (commit, commit_url, repo_url, last_commit, image_digest) — each None
        when its source is unavailable.
    """
    repo_dir = project_dir(name) / "repo"
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
    manifest_raw = _read_yaml_safe(project_dir(name) / "manifest.yml")
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

    repo_dir = project_dir(name) / "repo"
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

    Root, or membership in `nuk-facility`. A missing group is not an error —
    it means nobody has been granted the capability, so only root qualifies.
    """
    if os.geteuid() == 0:
        return True
    try:
        gid = grp.getgrnam(_FACILITY_GROUP).gr_gid
    except KeyError:
        return False
    return gid in os.getgroups()


def cmd_apply(manifest_path: Path, repo_path: str | None) -> None:  # noqa: C901, PLR0912, PLR0914, PLR0915  # linear apply pipeline; splitting it would scatter the reconcile order
    """Create or update a deployment from a manifest."""
    manifest_path = resolve_manifest(manifest_path)
    manifest = load(manifest_path)
    raw = manifest.raw
    name = manifest.metadata.name
    if manifest.kind == "Facility" and not _is_privileged():
        print(
            f"{name}: Facility apply requires root or membership in group "
            f"{_FACILITY_GROUP!r} (spec §4.4). Refusing."
        )
        sys.exit(1)
    role, self_ip = read_self()
    if not placement_matches(manifest, role):
        print(
            f"{name}: spec.placement.role={manifest.spec.placement.role!r} but this host "
            f"is role={role!r} — nothing to do"
        )
        return
    # The manifest's own directory is the tree root for a hand-run apply; the
    # convergence loop passes the archive root, whose facilities/ sits alongside.
    facilities = load_facilities(manifest_path.resolve().parent)
    vocab = route_vocabulary(facilities) if facilities else DEFAULT_ROUTE_VOCAB
    DYNAMIC.mkdir(parents=True, exist_ok=True)
    DEPLOYS.mkdir(parents=True, exist_ok=True)
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
    ingress = raw["spec"].get("ingress", []) or []
    db_env = provision_databases(name, raw["spec"].get("databases") or {}, facilities)
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
    # The edge renders EVERY router from the git tree (spec §6), so a non-edge host
    # no longer authors anything for it. It still PUBLISHES its container port on
    # its private IP — that is the backend the edge's router points at.
    edge_term = role not in _ENTRY_ROLES and bool(ingress)
    if edge_term and self_ip is None:
        sys.exit(
            f"{name}: host is non-edge (role={role}) but /etc/nuklaut/host.env has no "
            f"PRIVATE_IP — cannot publish ingress for the edge to reach"
        )
    write_override(name, ingress, db_env, env_from, db_services,
                   publish_ip=self_ip if edge_term else None)
    if edge_term:
        (DYNAMIC / f"{name}.yml").unlink(missing_ok=True)  # inert here; the edge owns it
    else:
        write_ingress(name, ingress, vocab)
    persist_manifest(raw, manifest_path, pdir / "manifest.yml", repo_path)
    # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
    # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
    # whose image id changed.
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
    if show_all:
        overview.update(_soll_vs_ist(overview, org_file))
    print(json.dumps(overview, indent=2 if pretty else None))


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
    return sorted(p.name for p in DEPLOYS.iterdir() if p.is_dir() and (p / "manifest.yml").exists())


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
