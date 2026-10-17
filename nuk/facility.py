#!/usr/bin/env python3
"""Facility manifests: loading, vocabulary, and the host's TreeContext.

Extracted from `nuk/__init__` during the module split.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

import nuk
from nuk.models import Deployment, Facility, load
from nuk.org import TENANTS_FILE, check_tenant_subnets, load_org, load_tenants
from nuk.util import die

if TYPE_CHECKING:
    from pathlib import Path

    from nuk.org import Org, TenantRegistry


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
        NukError: If two facilities declare the same capability. A closed
            vocabulary with two answers is not closed; picking one silently
            would let a manifest added to the tree shadow the real gate.
    """
    vocab: dict[str, list[str]] = {}
    for f in facilities:
        route = f.spec.provides.route
        if route is None:
            continue
        if route.capability in vocab:
            die(
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
    # The source's own repo URL (`sources.yml`): a tenant Deployment may name only this
    # repo as its payload repo — anything else is refused before a clone (cmd_apply).
    source_repo: str | None = None

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
        source_repo: str | None = None,
    ) -> TreeContext:
        """Load the platform-wide inputs from `platform` (default: `tree` itself)."""
        base = platform or tree
        from nuk import DEFAULT_ORG_FILE
        org_path = base / DEFAULT_ORG_FILE
        tenants_path = base / TENANTS_FILE
        org = load_org(org_path) if org_path.is_file() else None
        tenants = load_tenants(base) if tenants_path.is_file() else None
        if org is not None and tenants is not None:
            # The two halves of the tenant-bridge invariant live in different files, so
            # it cannot be an `Org` validator (design 2026-10-17 §D1).
            check_tenant_subnets(org, tenants)
        return cls(
            tree=tree,
            role=role,
            self_ip=self_ip,
            tenant=tenant,
            apply=apply,
            facilities=load_facilities(base, lenient=True),
            org=org,
            tenants=tenants,
            trees=trees if trees is not None else {"tag": tree},
            commits=commits if commits is not None else {},
            source_repo=source_repo,
        )

    @classmethod
    def for_path(cls, manifest_path: Path) -> TreeContext:
        """The context of a hand-run `nuk apply <manifest>`: this host, the manifest's own tree."""
        from nuk import read_self as _read_self
        role, self_ip = _read_self()
        return cls.build(_tree_root(manifest_path), role, self_ip, None, APPLY_ALL)


# The app host's router facility listens for plain-HTTP ingress from the edge on
# this port (infra: the `router` facility, placement {role: app}). When present,
# app deployments are fronted by it rather than dialled on their published port.
ROUTER_PORT = 8443


def _router_present(facilities: list[Facility]) -> bool:
    """Whether the fleet runs the `router` facility.

    The router lives in the PLATFORM source (contracts C3), so callers must pass
    the platform facilities (`ctx.facilities`) — never the source tree's own,
    which in the S1 topology ships deployments only (C4).
    """
    return any(f.metadata.name == "router" for f in facilities)


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
        exists, healthy = nuk._container_state(container)
        if not exists:
            return f"container {container!r} is not running"
        if not healthy:
            return f"container {container!r} is running but not healthy"
    return None
