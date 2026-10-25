#!/usr/bin/env python3
"""Ingress rendering: Traefik dynamic config, edge routers, backend addressing."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING

import yaml

import nuk

if TYPE_CHECKING:
    from nuk import HostAuth, Org
    from nuk.models import Deployment, Ingress


def public_url(ingress: list[Ingress]) -> str | None:
    """The app's canonical public URL, derived from its ingress hosts.

    An app needs one fixed, configured URL for OAuth callbacks, e-mails sent
    outside a request, and origin allowlists. Its manifest already names it: when
    the deployment's ingress resolves to exactly ONE distinct `host`, that host is
    canonical. Zero or several distinct hosts are ambiguous — a guess would point
    those flows at the wrong site — so nuk sets nothing and the app fails its own
    config check instead. `www: true` only adds a redirect to the same host.

    Args:
        ingress: The raw `spec.ingress[]` entries.

    Returns:
        `https://<host>` when exactly one distinct host is named, else None.
        Every nuk route terminates TLS, so the scheme is always https.
    """
    hosts = {ing.host for ing in ingress}
    if len(hosts) != 1:
        return None
    return f"https://{hosts.pop()}"


def build_override(  # noqa: C901, PLR0913, PLR0914, PLR0917  # frozen wire-contract API; one render pass
    name: str,  # noqa: ARG001  # kept for signature stability (frozen wire-contract API / tests)
    ingress: list[Ingress],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
    local_data: bool = True,
    *,
    colours: list[str] | None = None,
    public_url: str | None = None,
) -> nuk.ComposeOverride | None:
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
        env_from: Resolved `spec.envFrom` secret-file nuk.paths.
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
        colours: Blue-green colours to expand each service key across — e.g.
            ``["blue", "green"]`` renders ``backend-blue`` and ``backend-green``.
            Router mode (C3) passes this: the app-host router resolves each
            backend by its compose DNS name ``<service>-<colour>`` over the shared
            ``edge`` network, so the override must key on the profile-suffixed
            services, not the phantom base names. None (the default) leaves the
            service keys untouched.
        public_url: The app's configured public URL (see `public_url`). When set,
            every wired service's container env gets ``NUK_PUBLIC_URL`` via the
            override's own ``environment`` mapping, so it merges over the app
            compose file's ``environment`` (an ``env_file`` would lose to it).

    Returns:
        The override doc, or None when no service needs any wiring.
    """
    env_from = env_from or []
    # An address-only entry (a backend outside this host) has no compose service to wire.
    ingress_services = [ing.service for ing in ingress if ing.service is not None]
    db_targets = (list(ingress_services) if db_env else []) if db_services is None else db_services
    db_set = set(db_targets) if db_env else set()
    # Ingress order first, then any db-only (non-ingress) services, deduped.
    ordered = list(dict.fromkeys([*ingress_services, *db_targets]))
    # Worker edge-termination: collect the private-IP port bindings per service.
    # Bind on publish_ip (not 0.0.0.0) so the app stays reachable ONLY via the edge.
    publish_ports: dict[str, list[str]] = {}
    if publish_ip:
        for ing in ingress:
            svc, port = ing.service, ing.port
            if svc and port is not None:
                host_port = nuk._published_port(ing)
                mapping = f"{publish_ip}:{host_port}:{port}"
                publish_ports.setdefault(svc, [])
                if mapping not in publish_ports[svc]:
                    publish_ports[svc].append(mapping)
    services: dict[str, nuk.ServiceWiring] = {}
    environment = {"NUK_PUBLIC_URL": public_url} if public_url else {}
    uses_edge = False
    uses_data = False
    for svc_name in ordered:
        is_ingress = svc_name in ingress_services
        is_db = svc_name in db_set
        # Publishing on a private IP replaces the (inert) local `edge` join.
        nets = (["edge"] if is_ingress and not publish_ip else []) + (
            ["data"] if is_db and local_data else []
        )
        uses_edge = uses_edge or "edge" in nets
        uses_data = uses_data or "data" in nets
        env_files = [*env_from, *([db_env] if is_db and db_env else [])]
        # Router mode expands each base service onto its colour profile keys, so
        # the same wiring (networks, creds, no published port) lands on the
        # containers the router actually resolves.
        for key in [f"{svc_name}-{c}" for c in colours] if colours else [svc_name]:
            services[key] = nuk.ServiceWiring(
                networks=nets,
                ports=publish_ports.get(svc_name, []),
                env_file=env_files,
                environment=dict(environment),
            )
    if not services:
        return None
    external = [n for n, used in (("edge", uses_edge), ("data", uses_data)) if used]
    return nuk.ComposeOverride(services=services, external_networks=external)


def _rule(ing: Ingress) -> str:
    """Build the Traefik router rule for one ingress entry."""
    rule = f"Host(`{ing.host}`)"
    if ing.path:
        rule += f" && PathPrefix(`{ing.path}`)"
    return rule


def write_ingress(
    name: str,
    ingress: list[Ingress],
    vocab: dict[str, list[str]],
    *,
    colour: str | None = None,
    dialect: str = "edge",
) -> None:
    """Render and write the Traefik dynamic file for an app (removes it if empty).

    `colour` threads the blue-green colour into `build_ingress` (see there).
    `dialect` selects the edge or mesh entrypoint/TLS flavour (see there).
    """
    target = nuk._router_file(name)
    doc = nuk.build_ingress(name, ingress, vocab, colour=colour, dialect=dialect)
    if doc is None:
        target.unlink(missing_ok=True)
        return
    text = yaml.safe_dump(doc.to_wire())
    # Every write is an fsnotify event that makes Traefik rebuild its whole dynamic
    # config, and the loop re-applies every cycle — skip identical content.
    try:
        if target.read_text() == text:
            return
    except OSError:
        pass
    target.write_text(text)


def backend_address(
    org: Org, manifest: Deployment, ing: Ingress, *, router_present: bool = False
) -> str:
    """Where the edge should send traffic for one ingress entry.

    An explicit `address` (a backend the org does not manage) passes through.
    Otherwise the backend is the private IP of the org's host for this
    deployment's `placement.role`, on the published port — the port
    build_override publishes, which is `hostPort` when set and `port` otherwise.

    When the fleet runs the `router` facility, an app-role deployment is instead
    fronted by that router on `nuk.ROUTER_PORT`: the app host's Traefik terminates the
    route, so the edge dials the router, not the container's published port.

    Raises:
        ValueError: If the deployment has no placement (the edge cannot guess
            which host runs it), the org declares no host with that role, the role
            has several hosts and none is marked default (ambiguous), or the
            placement names a `host` the org does not declare.
    """
    if ing.address:
        return ing.address
    placement = manifest.spec.placement
    if placement is None:
        msg = (
            f"{manifest.metadata.name}: has ingress but no spec.placement — the edge "
            f"cannot resolve a backend without knowing which host runs it."
        )
        raise ValueError(msg)
    if placement.host is not None:
        host = org.host_named(placement.host)
        if host is None:
            msg = (
                f"{manifest.metadata.name}: placement.host={placement.host!r} but the "
                f"org manifest declares no host with that name."
            )
            raise ValueError(msg)
        if host.role != placement.role:
            # placement_matches gates the pin behind `placement.role == self role`,
            # so a pin to another role's host matches NO host on converge. The edge
            # must refuse it too, not emit a route nothing serves.
            msg = (
                f"{manifest.metadata.name}: placement.host={placement.host!r} has role "
                f"{host.role!r}, not {placement.role!r} — no host runs this placement."
            )
            raise ValueError(msg)
    else:
        # No `or host_for` fallback: several hosts and no default is AMBIGUOUS, and
        # picking the first would disagree with placement_matches (which raises).
        host = org.default_host(placement.role)
        if host is None:
            of_role = [h for h in org.hosts if h.role == placement.role]
            if not of_role:
                msg = (
                    f"{manifest.metadata.name}: placement.role={placement.role!r} but the org "
                    f"manifest declares no host with role {placement.role!r}."
                )
            else:
                msg = (
                    f"{manifest.metadata.name}: placement.role={placement.role!r} is ambiguous — "
                    f"{len(of_role)} hosts and none marked default; set spec.placement.host or a "
                    f"host default."
                )
            raise ValueError(msg)
    if router_present and placement.role == "app":
        return f"{host.private_ip}:{nuk.ROUTER_PORT}"
    return f"{host.private_ip}:{nuk._published_port(ing)}"


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
    if not nuk.paths.DYNAMIC.is_dir():
        return []
    protected = protected or set()
    reaped = []
    for p in sorted(nuk.paths.DYNAMIC.glob(f"{_LEGACY_ROUTER_PREFIX}*.yml")):
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


def _refuse_route(host: str, owner: str | None, refused: list[str]) -> None:
    """Record and announce a host this source is not authorized to render (spec §3/§6)."""
    line = f"REFUSED route {host}: owned/delegated by {owner or 'the platform'}"
    refused.append(line)
    print(line, file=sys.stderr)


def _authorized_ingress(
    ingress: list[Ingress], tenant: str, auth: HostAuth | None, refused: list[str]
) -> list[Ingress]:
    """The ingress entries a tenant source may render, `www.` included (spec §3/§6).

    A host resolving to anyone but `tenant` is refused. `www.<host>` is a second,
    independently-resolved host: the same loan that authorizes `<host>` must cover it
    too, or the redirect router is an unauthenticated hijack vector. Without that
    coverage the variant is dropped — the apex router still renders.
    """
    allowed: list[Ingress] = []
    for ing in ingress:
        host = ing.host
        owner = auth.resolve(host) if auth is not None else None
        if owner != tenant:
            _refuse_route(host, owner, refused)
            continue
        entry = ing
        if ing.www:
            www_host = f"www.{host}"
            www_owner = auth.resolve(www_host) if auth is not None else None
            if www_owner != tenant:
                _refuse_route(www_host, www_owner, refused)
                entry = ing.model_copy(update={"www": False})
        allowed.append(entry)
    return allowed


def render_edge_routers(tree: Path, org: Org) -> list[str]:
    """The platform edge render: every host, no tenant gate. Returns the names written."""
    return nuk._render_routers(tree, org, tenant=None, auth=None).rendered
