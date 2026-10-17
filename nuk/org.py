#!/usr/bin/env python3
"""Org, tenant registry, delegation, cross-zone authority (nukorg/v1).

Extracted from `nuk/__init__` during the module split.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Annotated, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from nuk.models import Metadata, Role, _NullTolerant
from nuk.util import die

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

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
    # The default host for its role: where an UNPINNED deployment of that role runs
    # when the role has more than one host (spec §13 selector follow-up).
    default: bool = False
    # The tenant whose own bridge this host sits on, if any (design 2026-10-17 §D1).
    # Such a host is validated against that tenant's bridge CIDR, not `vswitchSubnet`.
    tenant: str | None = None


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


_SINGLETON_ROLES = frozenset({"data"})


def _check_singleton_roles(hosts: list[Host]) -> None:
    """Raise unless placement-target roles are 1:1 with hosts (spec §3.1).

    `edge`/`all-in-one` are already exactly-one via `_check_entry_and_mesh`;
    `hypervisor` is exempt — placement never targets it, and the broker needs
    multi-metal to be legal. `app` is multi-host as of the selector work (§13):
    an org may declare a second app host (e.g. a dedicated Kolbe VM), selected
    via the placement `host` field; only `data` stays singleton. Multi-host
    `data` remains future work; the seam is a `selector:` on placement.
    """
    for role in sorted(_SINGLETON_ROLES):
        named = [h.name for h in hosts if h.role == role]
        if len(named) > 1:
            msg = (
                f"at most one host may have role {role!r} "
                f"(placement is a singleton model today) — found: {', '.join(named)}"
            )
            raise ValueError(msg)


def _check_one_default_per_role(hosts: list[Host]) -> None:
    """Raise if any role marks more than one host `default: true`."""
    for role in {h.role for h in hosts}:
        marked = [h.name for h in hosts if h.role == role and h.default]
        if len(marked) > 1:
            msg = f"at most one default host per role {role!r} — found: {', '.join(marked)}"
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
    """Raise unless every host's private IP sits in its provider's declared subnet.

    Two kinds of host are skipped: the hypervisor (its privateIp is a management IP, not
    an app subnet) and a host declaring a `tenant` — that host is placed on its tenant's
    own bridge and is validated against that bridge's CIDR by `check_tenant_subnets`,
    the only place with the tenant registry in hand.
    """
    for h in hosts:
        if h.role == "hypervisor" or h.tenant is not None:
            continue
        cloud = h.provider == "hcloud"
        subnet = network.cloud_subnet if cloud else network.vswitch_subnet
        if not _ip_in_cidr(h.private_ip, subnet):
            field = "cloudSubnet" if cloud else "vswitchSubnet"
            msg = f"host {h.name}: privateIp {h.private_ip} is not in {field} {subnet}"
            raise ValueError(msg)


def check_tenant_subnets(org: Org, registry: TenantRegistry) -> None:
    """Raise unless every tenant host sits on the bridge its tenant declares.

    The registry (`tenants.yml`) and the org manifest are different files, so this cannot
    be an `Org` validator: it needs both. A host with no `tenant` keeps `Org`'s own
    fleet-subnet rule.

    Raises:
        ValueError: On a tenant host outside its tenant's bridge CIDR, a `tenant` the
            registry does not declare, or a tenant row that declares no bridge.
    """
    for h in org.hosts:
        if h.tenant is None:
            continue
        tenant = registry.get(h.tenant)
        if tenant is None:
            msg = f"{h.name}: tenant {h.tenant} is not in tenants.yml"
            raise ValueError(msg)
        if tenant.bridge is None:
            msg = f"{h.name}: tenant {h.tenant} declares no bridge in tenants.yml"
            raise ValueError(msg)
        if not _ip_in_cidr(h.private_ip, tenant.bridge.cidr):
            msg = (
                f"{h.name}: privateIp {h.private_ip} is not in tenant {tenant.name} "
                f"bridge {tenant.bridge.name} {tenant.bridge.cidr}"
            )
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
                at most one host per placement-target role, at most one default
                host per role, platformDomain membership, and private-IP subnet
                placement).
        """
        _check_domains(self.platform_domain, self.domains)
        _check_unique(self.hosts)
        _check_entry_and_mesh(self.hosts, self.mesh)
        _check_singleton_roles(self.hosts)
        _check_one_default_per_role(self.hosts)
        _check_vm_hosts(self.hosts)
        if self.network is not None:
            _check_subnets(self.hosts, self.network)
        return self

    def host_for(self, role: str) -> Host | None:
        """The host carrying `role`, or None (placement-target roles are singletons)."""
        return next((h for h in self.hosts if h.role == role), None)

    def host_named(self, name: str) -> Host | None:
        """The host with this `name`, or None."""
        return next((h for h in self.hosts if h.name == name), None)

    def app_host_count(self) -> int:
        """How many hosts carry role `app` (the multi-host role)."""
        return sum(1 for h in self.hosts if h.role == "app")

    def default_host(self, role: str) -> Host | None:
        """The role's default host: the `default: true` one, or its sole host."""
        of_role = [h for h in self.hosts if h.role == role]
        marked = [h for h in of_role if h.default]
        if marked:
            return marked[0]
        if len(of_role) == 1:
            return of_role[0]
        return None


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
        NukError: If the file is unreadable or not a valid nukorg/v1 Org.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        die(f"{path}: {e}")
    try:
        return Org.model_validate(raw)
    except ValidationError as e:
        die(f"{path}: invalid nukorg/v1 Org\n{e}")


# --- tenant registry (bartixcloud/infra/tenants.yml, contracts C2) ------------------
# The platform repo owns the schema and its validator. nuk models only the fields it
# consumes and re-checks the invariant its own isolation depends on: unique names and
# no two tenants claiming the same domain pattern (spec §1/§3).

TENANTS_FILE = "tenants.yml"
DELEGATIONS_FILE = "delegations.yml"
DELEGATIONS_CACHE_FILE = "delegations.json"


class Bridge(BaseModel):
    """A tenant's own Incus bridge: the network its app hosts sit on."""

    name: str
    cidr: str


class TenantRow(BaseModel):
    """One `tenants[]` row, as far as nuk reads it.

    `tenants.yml` is the shared platform registry (the runner broker's
    `bcx-gen-tenant-env` reads the same file and tolerates unknown keys). nuk models
    `name`, the edge allowlist `domains`, and the tenant's own `bridge`; any other field
    is ignored.
    """

    model_config = ConfigDict(extra="ignore")

    name: str = Field(pattern=r"^[a-z0-9-]+$")
    domains: list[str] = []
    edge: Literal["shared", "passthrough"] | None = None
    signer_principal: str | None = None
    bridge: Bridge | None = None


def specificity(pattern: str) -> int:
    """The pattern's specificity: its number of literal labels (spec §3).

    A `*.` label is not literal, so `*.c` ranks like `c`. Neither this function nor the
    resolver breaks a tie: a specificity tie between two tenants is structurally
    impossible, because `TenantRegistry._check_unique` already rejects a pattern two
    tenants both list, and two distinct patterns that both cover one host cannot share a
    rank.
    """
    return len([label for label in pattern.lower().split(".") if label != "*"])


class TenantRegistry(BaseModel):
    """The `tenants:` list of tenants.yml."""

    tenants: list[TenantRow]

    @model_validator(mode="after")
    def _check_unique(self) -> TenantRegistry:
        """Refuse duplicate tenant names and any domain pattern two tenants both claim.

        Overlap between tenants is allowed (spec §1: one owns a zone, another may be
        lent a subdomain); only the *same* pattern — compared case-insensitively — is
        a conflict.

        Raises:
            ValueError: On either violation.
        """
        names = [t.name for t in self.tenants]
        if len(names) != len(set(names)):
            msg = "tenants[].name must be unique"
            raise ValueError(msg)
        seen: set[str] = set()
        for t in self.tenants:
            for domain in t.domains:
                key = domain.lower()
                if key in seen:
                    msg = f"domain pattern {domain!r} is claimed by more than one tenant"
                    raise ValueError(msg)
                seen.add(key)
        return self

    def get(self, name: str) -> TenantRow | None:
        """The row for tenant `name`, or None."""
        return next((t for t in self.tenants if t.name == name), None)


class Delegation(_NullTolerant):
    """One borrowed host: `host` (a §1 pattern) is lent to tenant `to` (spec §2).

    Lives in the owner's `delegations.yml`; the loader (Task 3) fills it. Both
    fields are trimmed and non-empty.
    """

    host: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    to: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


class DelegationsSpec(_NullTolerant):
    """`spec` of a `Delegations` document — the hosts the owner lends out."""

    delegations: list[Delegation] = Field(default_factory=list)


class Delegations(_NullTolerant):
    """The `<tenant-tree>/delegations.yml` document (spec §2): one tenant's loans."""

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nuk/v1"] = Field(alias="apiVersion")
    kind: Literal["Delegations"]
    metadata: Metadata
    spec: DelegationsSpec = DelegationsSpec()


def load_delegations(tree: Path) -> list[Delegation]:
    """Parse `<tree>/delegations.yml`, the owner's loans (spec §2).

    A tree without the file lends nothing (returns `[]`); a malformed one is a
    refusal, not a silent skip.

    Raises:
        NukError: If the file is unreadable or invalid.
    """
    path = tree / DELEGATIONS_FILE
    if not path.is_file():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        die(f"{path}: {e}")
    try:
        return Delegations.model_validate(raw).spec.delegations
    except ValidationError as e:
        die(f"{path}: invalid delegations manifest\n{e}")


def store_delegations(state_dir: Path, owner: str, dels: list[Delegation]) -> None:
    """Persist `owner`'s last verified loans under its source state (spec §4).

    Overwritten on every successful fetch, so the cache always holds the newest
    VERIFIED state and never a merely fetched one.
    """
    from nuk import source_state_dir
    path = source_state_dir(state_dir, owner) / DELEGATIONS_CACHE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = Delegations(
        apiVersion="nuk/v1",
        kind="Delegations",
        metadata=Metadata(name=owner),
        spec=DelegationsSpec(delegations=dels),
    )
    path.write_text(doc.model_dump_json(by_alias=True) + "\n", encoding="utf-8")


def load_cached_delegations(state_dir: Path, owner: str) -> list[Delegation]:
    """The last verified loans of `owner`, or `[]` when none are cached (spec §4).

    A missing cache lends nothing (fail-closed: the first run has no loans yet); a
    corrupt one is a refusal, like a malformed `delegations.yml`.

    Raises:
        NukError: If the cache exists but is unreadable or invalid.
    """
    from nuk import source_state_dir
    path = source_state_dir(state_dir, owner) / DELEGATIONS_CACHE_FILE
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        die(f"{path}: {e}")
    try:
        return Delegations.model_validate_json(raw).spec.delegations
    except ValidationError as e:
        die(f"{path}: invalid cached delegations\n{e}")


def load_tenants(tree: Path) -> TenantRegistry:
    """Parse `<tree>/tenants.yml` (the platform tree).

    Raises:
        NukError: If the file is unreadable or invalid.
    """
    path = tree / TENANTS_FILE
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as e:
        die(f"{path}: {e}")
    try:
        return TenantRegistry.model_validate(raw)
    except ValidationError as e:
        die(f"{path}: invalid tenants registry\n{e}")


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


def _owner_of(host: str, claims: Iterable[tuple[str, list[str]]]) -> tuple[str, int] | None:
    """The `(tenant, specificity)` of the most specific claim covering `host`: its zone owner.

    `claims` is a stream of `(tenant name, owned patterns)`. This is spec §3.1's zone
    owner — the tenant `resolve_host_owner` starts from and then subtracts delegations
    from. A tie between two tenants is structurally impossible once
    `TenantRegistry._check_unique` rejects duplicate patterns; `die` anyway rather than
    pick a winner (spec §3.5: the resolution must never be non-deterministic).
    """
    best: tuple[str, int] | None = None
    for name, domains in claims:
        for pattern in domains:
            if not host_in_domains(host, [pattern]):
                continue
            rank = specificity(pattern)
            if best is None or rank > best[1]:
                best = (name, rank)
            elif rank == best[1] and name != best[0]:
                die(f"nuk: host {host!r} is claimed by both {best[0]!r} and {name!r}")
    return best


def _claims(registry: TenantRegistry) -> list[tuple[str, list[str]]]:
    """Each tenant's `(name, owned patterns)` pairs, in registry order."""
    return [(t.name, t.domains) for t in registry.tenants]


def _resolve(
    host: str,
    claims: Iterable[tuple[str, list[str]]],
    delegations: dict[str, list[Delegation]],
) -> str | None:
    """The authorized tenant for `host`: its zone owner, minus the most specific covering loan.

    A delegation transfers only when its `host` covers `host` **and** is at least as
    specific as the owned pattern that made its owner the zone owner — a delegation
    broader than the owner's winning claim does not reach this host (spec §3.2). Among
    several qualifying loans the most specific wins, so a loan is not shadowed by a
    broader one earlier in the owner's `delegations.yml`.
    """
    match = _owner_of(host, claims)
    if match is None:
        return None
    owner, owner_rank = match
    best: Delegation | None = None
    best_rank = -1
    for delegation in delegations.get(owner, []):
        if not host_in_domains(host, [delegation.host]):
            continue
        rank = specificity(delegation.host)
        if rank < owner_rank or rank <= best_rank:
            continue
        best, best_rank = delegation, rank
    return best.to if best is not None else owner


def resolve_host_owner(
    host: str,
    registry: TenantRegistry,
    delegations: dict[str, list[Delegation]],
) -> str | None:
    """The tenant authorized to render `host`: its zone owner minus delegations (spec §3).

    Returns None when no tenant owns `host` (a platform name, spec §6).
    """
    return _resolve(host, _claims(registry), delegations)


def check_cross_zone_patterns(
    tenant: str,
    registry: TenantRegistry,
    delegations: dict[str, list[Delegation]],
) -> None:
    """Refuse a pattern of `tenant` that falls into another tenant's zone without a delegation.

    A `domains` entry lying in another tenant's zone is not an authorization — it is the
    very overlap that must not grant rights (spec §3.3). The owning tenant must delegate it
    to `tenant`. The check excludes `tenant`'s own patterns when deciding whose zone a
    pattern falls in (otherwise the pattern would "own itself" by specificity). Judging one
    tenant at a time lets the cycle refuse the offending source rather than the whole run.

    Raises:
        NukError: For the first such undelegated foreign pattern.
    """
    row = registry.get(tenant)
    if row is None:
        return
    others = [(t.name, t.domains) for t in registry.tenants if t.name != tenant]
    for pattern in row.domains:
        owner = _owner_of(pattern, others)
        if owner is None:
            continue
        if _resolve(pattern, others, delegations) != tenant:
            die(
                f"nuk: tenant {tenant!r} lists {pattern!r}, which falls in "
                f"{owner[0]!r}'s zone and is not delegated to it"
            )


def validate_delegations(owner: str, dels: list[Delegation], registry: TenantRegistry) -> None:
    """Check one owner's loans before they are honoured (spec §2).

    Four refusals: the owner must be the *zone owner* of the lent host — not merely list a
    broader pattern covering it, which would make the loan a no-op (coverage), no host may
    be lent twice (a specificity tie the resolver must not have to break), the target
    tenant must exist, and the target must not list the host itself — listing it would make
    the target a competing owner and let it lend the host on (one-level rule).

    Raises:
        NukError: On any of the four.
    """
    row = registry.get(owner)
    if row is None:
        die(f"nuk: tenant {owner!r} has delegations but is not in the registry")
    seen: set[str] = set()
    for d in dels:
        key = d.host.lower()
        if key in seen:
            die(f"nuk: tenant {owner!r} delegates {d.host!r} more than once")
        seen.add(key)
        zone = _owner_of(d.host, _claims(registry))
        if zone is None or zone[0] != owner:
            die(f"nuk: tenant {owner!r} cannot delegate {d.host!r}, which it does not own")
        target = registry.get(d.to)
        if target is None:
            die(f"nuk: tenant {owner!r} delegates {d.host!r} to unknown tenant {d.to!r}")
        if d.to != owner and host_in_domains(d.host, target.domains):
            die(
                f"nuk: tenant {d.to!r} lists {d.host!r} itself; a delegated host may be "
                f"listed only by its owner {owner!r} (no re-delegation)"
            )
