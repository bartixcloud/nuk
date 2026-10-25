#!/usr/bin/env python3
"""Apply / rollback / delete command layer."""

from __future__ import annotations

import grp
import json
import os
import shlex
import shutil
import subprocess  # noqa: S404
import sys
from dataclasses import replace
from pathlib import Path  # noqa: TC003

import typer
import yaml

import nuk
from nuk.models import ValidationError  # noqa: TC003

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
    return (
        left is not None
        and right is not None
        and nuk._repo_identity(left) == nuk._repo_identity(right)
    )


def cmd_apply(  # noqa: C901, PLR0912, PLR0914, PLR0915  # linear apply pipeline; splitting it would scatter the reconcile order
    manifest_path: Path,
    repo_path: str | None,
    *,
    ctx: nuk.TreeContext | None = None,
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
    manifest_path = nuk.resolve_manifest(manifest_path)
    manifest = nuk.load(manifest_path)
    name = manifest.metadata.name
    if manifest.kind == "Facility" and not nuk._is_privileged():
        print(
            f"{name}: Facility apply requires root or membership in group "
            f"{_FACILITY_GROUP!r} (spec §4.4). Refusing."
        )
        sys.exit(1)
    ctx = ctx or nuk.TreeContext.for_path(manifest_path)
    role, self_ip = ctx.role, ctx.self_ip
    if not nuk.placement_matches(manifest, role, self_ip=self_ip, org=ctx.org):
        # nuk.placement_matches returns False only when a placement is set and differs.
        placement = manifest.spec.placement
        assert placement is not None  # noqa: S101  # narrows the union for ty
        print(
            f"{name}: spec.placement.role={placement.role!r} but this host "
            f"is role={role!r} — nothing to do"
        )
        return
    facilities = ctx.facilities
    vocab = nuk.route_vocabulary(facilities) if facilities else nuk.DEFAULT_ROUTE_VOCAB
    # Router mode (C1): the fleet runs the `router` facility, which is placed on an
    # app host and terminates HTTP on the private `mesh` entrypoint — no TLS, no
    # edge `global.yml`. This host therefore writes its app file router in the mesh
    # dialect. The gate on `role == "app"` keeps an entry host (which sits alongside
    # the edge Traefik and still renders edge-dialect routers) on the edge dialect.
    #
    # A facilities-less context — a hand-run apply, or the digest-path re-apply
    # `cmd_rollback` drives through `nuk.cmd_apply(..., ctx=None)` — cannot see the
    # platform `router` facility (the persisted manifest dir ships no facilities/).
    # Fall back to the dialect the last apply recorded (Task 16) so a router-mode app
    # keeps its app-host file router instead of unlinking it below; an unrecorded app
    # reads `edge` and keeps the legacy behaviour.
    router_present = nuk._router_present(facilities)
    if not facilities:
        router_present = nuk.router_dialect(name) == "mesh"
    router_mode = role == "app" and router_present
    # Only the mesh write carries the dialect; the edge-dialect call stays
    # byte-identical to what every existing caller and test double expects.
    mesh_kwargs = {"dialect": "mesh"} if router_mode else {}
    nuk.paths.DYNAMIC.mkdir(parents=True, exist_ok=True)
    nuk.paths.DEPLOYS.mkdir(parents=True, exist_ok=True)
    source = manifest.spec.source
    if ctx.tenant is not None and source.repo and not nuk._same_repo(source.repo, ctx.source_repo):
        # The tree is the review unit (P1): a tenant source may ship its compose payload
        # under deployments/<name>/, or name the tenant's OWN repo — the one whose signed
        # tag this cycle verified. Naming any other repo would have the app host clone it
        # as root with ambient credentials, and the signed-tag pin could never resolve
        # there. Refuse before anything is fetched.
        nuk.die(
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
    pdir = nuk.project_dir(name)
    pdir.mkdir(parents=True, exist_ok=True)
    repo = pdir / "repo"
    if repo_path:
        # Workflow-managed: caller already has a checkout; mirror it in place.
        # rsync -a --delete keeps repo/ identical to the source tree.
        nuk.sh(
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
            nuk.sh("git", "clone", "--branch", branch, source.repo, str(repo))
        elif pin_commit:
            nuk.sh("git", "-C", str(repo), "fetch", "--quiet")
        else:
            nuk.sh("git", "-C", str(repo), "checkout", branch)
            nuk.sh("git", "-C", str(repo), "pull", "--ff-only", "--quiet")
        if pin_commit:
            # Rollback. The branch checkout + ff-only pull above is skipped rather
            # than followed by a detach, because pulling first would fetch the very
            # tip we are rolling away from and leave the tree at it if the detach
            # then failed.
            nuk.sh("git", "-C", str(repo), "checkout", "--quiet", "--detach", pin_commit)
    elif declaration_only:
        pass  # nothing to mirror — the manifest IS the whole facility
    else:
        # A sourceless manifest — a Facility like data-stack, or a Deployment whose
        # compose ships with the tree — carries its payload beside its manifest at
        # <tree>/facilities|deployments/<name>/ (the manifest's own directory is the
        # tree root for a hand-run apply, the archive root for the loop). Mirror it
        # into the project dir exactly like a cloned repo, so nuk.compose_args' existing
        # `-f repo/<file>` resolution works unchanged. rsync --delete converges
        # repo/ in place: removing it first would hand running containers a new
        # inode under their bind mounts on every cycle.
        payload = manifest_path.resolve().parent / name
        if not payload.is_dir():
            where = f"{manifest_path.resolve().parent.name}/{name}/"
            nuk.die(
                f"{manifest_path}: {manifest.kind} {name} has no source.repo and no "
                f"{where} payload directory — nothing to apply"
            )
        nuk.sh("rsync", "-a", "--delete", f"{payload}/", str(repo) + "/")
    if pin_digest:
        nuk._pin_image(name, manifest.spec, pin_digest)
    ingress = manifest.spec.ingress
    org = ctx.org
    remote_ip = None
    if org is not None:
        # The remote decision mirrors provision_remote_databases's owner gate
        # exactly (spec §3.1): this host provisions locally iff it owns the
        # `databases` capability. Keying on `role != "data"` diverges for an
        # all-in-one host, which nuk.placement_matches treats as owner of every
        # facility — the two sides must never disagree.
        owner = nuk.env_facility(facilities, nuk._DATABASES_CAPABILITY)
        owns_databases = owner is not None and nuk.placement_matches(
            owner, role, self_ip=self_ip, org=org
        )
        if not owns_databases:
            remote_ip = nuk.data_host_ip(org)
    db_env = nuk.provision_databases(name, manifest.spec.databases, facilities, remote_ip=remote_ip)
    db_services = nuk.resolve_db_services(name, manifest.spec, db_env)
    if db_env and not db_services:
        print(
            f"{name}: databases provisioned but no service to attach them to — "
            f"DATABASE_URL/REDIS_URL won't be injected. Add an ingress entry, or set "
            f"spec.databases.attachTo / attachAll to target a worker."
        )
    env_from = nuk.resolve_env_from(manifest.spec)
    if env_from and not ingress:
        print(
            f"{name}: spec.envFrom secrets resolved but no ingress service to "
            f"attach them to — they won't be injected. Add an ingress entry."
        )
    # The edge renders EVERY router from the git tree (spec §6), so a non-edge host
    # no longer authors anything for it. It still PUBLISHES its container port on
    # its private IP — that is the backend the edge's router points at.
    edge_term = role not in nuk._ENTRY_ROLES and bool(ingress)
    if edge_term and self_ip is None:
        nuk.die(
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
    # The app's own PUBLIC_URL is derived, never copied by hand: exactly one
    # ingress host is canonical, anything else is ambiguous. nuk never guesses.
    public_url = nuk.public_url(ingress)
    if ingress and public_url is None:
        print(
            f"{name}: ingress serves {len({ing.host for ing in ingress})} hosts — "
            f"NUK_PUBLIC_URL not set"
        )
    nuk.write_override(
        name,
        ingress,
        db_env,
        env_from,
        db_services,
        publish_ip=self_ip if (edge_term and not router_mode) else None,
        local_data=remote_ip is None,
        colours=router_colours,
        public_url=public_url,
    )
    migrate = manifest.spec.migrate
    if manifest.kind == "Deployment" and migrate is not None and pin_digest is None:
        # Before the rollout. A digest-path rollback (`pin_digest`, set only by
        # `cmd_rollback`) never migrates — forward-only, and the recorded
        # revision it restores may predate the current migration head. A
        # blue-green colour flip never reaches here at all.
        key = nuk._rollout_key(name, manifest.spec, migrate, strategy)
        if key is None or key != nuk.migrated_digest(name):
            nuk._run_migrations(name, manifest.spec, migrate, strategy, key)
    if strategy is not None and strategy.type == "blue-green":
        # Blue-green replaces "ingress -> up -d" with a colour rollout: bring the
        # idle colour up (its compose profile), gate on its health, flip the
        # app-host file router to it, record it, then drain the old colour. The
        # app host owns its own router here (the edge routes stably to it), so
        # the colourless `edge_term` unlink below is deliberately bypassed.
        nuk.persist_manifest(manifest.spec, manifest_path, pdir / "manifest.yml", repo_path)
        nuk._apply_blue_green(name, manifest.spec, ingress, vocab, strategy, **mesh_kwargs)
    else:
        if edge_term and not router_mode:
            nuk._router_file(name).unlink(missing_ok=True)  # inert here; the edge owns it
        else:
            nuk.write_ingress(name, ingress, vocab, **mesh_kwargs)
        # Record the dialect this apply decided (write OR unlink) so a later
        # facilities-less re-apply — the digest-path rollback — re-decides router mode
        # from the marker rather than guessing `edge` and unlinking the app-host router.
        nuk.record_router_dialect(name, "mesh" if router_mode else "edge")
        nuk.persist_manifest(manifest.spec, manifest_path, pdir / "manifest.yml", repo_path)
        # No --pull here: the deploy user has no GHCR auth. Images are pre-pulled by
        # the runner (nuk-apply.yml) into the shared daemon; up -d recreates services
        # whose image id changed. A declaration-only Facility has no compose file at
        # all — there is nothing to bring up.
        if not declaration_only:
            nuk.sh(*nuk.compose_args(name, manifest.spec), "up", "-d")
    # An unhealthy facility must not become "current": nuk.write_provenance is what
    # `nuk status`, `nuk rollback` and drift.nuk.sh read as the deployed state, so
    # appending here would both hide the breakage and put the last known-good
    # entry out of rollback's reach (spec §5.4).
    if manifest.kind == "Facility" and (reason := nuk.facility_health(manifest)) is not None:
        nuk.die(f"{name}: facility is not healthy — {reason}. Provenance not appended.")
    # Provenance is best-effort: `status` prefers it over the live repo/ checkout
    # (trustworthy even for rsync-mirrored, .git-less workflow deploys), but a
    # write failure here must never fail an otherwise-successful apply.
    try:
        nuk.write_provenance(
            name,
            repo=source.repo,
            branch=source.branch,
            commit=nuk._full_commit_sha(repo) if (repo / ".git").exists() else None,
            image_digest=nuk._resolve_image_digest(name, manifest.spec),
        )
    except OSError as e:
        print(f"{name}: provenance not recorded ({e})")


def _migrate_colour(name: str, strategy: nuk.Strategy | None) -> str | None:
    """The idle colour a migration targets, or None for a colourless app.

    A blue-green deployment's compose services are colour-suffixed
    (`backend-blue`), and the migration must run the image the rollout is about
    to bring up — so, like the health probe (`strategy.health.service`), the
    service is suffixed with the idle colour and its compose profile enabled.
    """
    if strategy is not None and strategy.type == "blue-green":
        return nuk.idle_colour(nuk.active_colour(name))
    return None


def _migrate_service(name: str, migrate: nuk.Migrate, strategy: nuk.Strategy | None) -> str:
    """The compose service the migration runs in (colour-suffixed when blue-green)."""
    colour = nuk._migrate_colour(name, strategy)
    return f"{migrate.service}-{colour}" if colour else migrate.service


def _run_migrations(
    name: str,
    spec: nuk.Spec,
    migrate: nuk.Migrate,
    strategy: nuk.Strategy | None,
    digest: str | None,
) -> None:
    """Run the deployment's one-shot migration, failing the deploy on any error.

    The compose service supplies the image, env and network; nuk supplies the
    argv. A non-zero exit propagates as `CalledProcessError` (the apply pipeline
    records the manifest `failed`), a timeout becomes a fail-closed `SystemExit`.
    The digest is recorded only after success, so a crash mid-migration re-runs.
    """
    service = nuk._migrate_service(name, migrate, strategy)
    colour = nuk._migrate_colour(name, strategy)
    profile = ["--profile", colour] if colour else []
    argv = [
        *nuk.compose_args(name, spec),
        *profile,
        "run",
        "--rm",
        "--no-deps",
        service,
        *shlex.split(migrate.command),
    ]
    print(f"{name}: migrating ({service}: {migrate.command})")
    try:
        nuk.sh(*argv, timeout=migrate.timeout)
    except subprocess.TimeoutExpired:
        # SIGKILL reaches the compose client, not the container it started; stop
        # the one-off by hand so a hung migration cannot keep running against the DB.
        subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*nuk.compose_args(name, spec), "rm", "-sf", service], check=False
        )
        nuk.die(f"{name}: migration timed out after {migrate.timeout}s — deploy aborted")
    except subprocess.CalledProcessError as e:
        nuk.die(f"{name}: migration failed (exit {e.returncode}): {migrate.command}")
    if digest:
        nuk.record_migrated_digest(name, digest)


def _apply_blue_green(  # noqa: PLR0913  # name/spec/ingress/vocab/strategy/dialect, one per concern
    name: str,
    spec: nuk.Spec,
    ingress: list[nuk.Ingress],
    vocab: dict[str, list[str]],
    strategy: nuk.Strategy,
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
        spec: The manifest `spec` (for `nuk.compose_args`).
        ingress: The `spec.ingress[]` routes.
        vocab: Route capabilities resolved from the tree.
        strategy: The parsed `spec.strategy` block.
        dialect: The file-router dialect the flip writes; `"mesh"` on a router-mode
            app host, `"edge"` otherwise (see `build_ingress`).
    """
    active = nuk.active_colour(name)
    idle = nuk.idle_colour(active)
    health = strategy.health
    nuk.sh(*nuk.compose_args(name, spec), "--profile", idle, "up", "-d")
    # Resolve `nuk.sh` at call time (nuk.await_healthy's default binds the original at
    # import), so the probe runs through the same runner this host is configured
    # to use — and tests can capture it.
    nuk.await_healthy(
        nuk._container_name(name, health.service, idle),
        health.path,
        timeout=health.timeout,
        interval=health.interval,
        port=health.port or 8000,
        exec_=nuk.sh,
    )
    nuk.write_ingress(name, ingress, vocab, colour=idle, dialect=dialect)
    nuk.record_active_colour(name, idle)
    nuk.record_router_dialect(name, dialect)
    if not strategy.keep_previous:
        # Drain every service the deployment publishes — the probe service plus
        # each ingress backend — so a manifest that names them other than the
        # conventional backend/frontend still tears the old colour fully down.
        # dict.fromkeys dedups while preserving manifest order.
        published = dict.fromkeys([health.service, *(i.service for i in ingress if i.service)])
        nuk.sh(
            *nuk.compose_args(name, spec),
            "--profile",
            active,
            "down",
            *(f"{service}-{active}" for service in published),
        )


def _rollback_blue_green(
    name: str,
    spec: nuk.Spec,
    ingress: list[nuk.Ingress],
    vocab: dict[str, list[str]],
    strategy: nuk.Strategy,
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
    previous = nuk.idle_colour(nuk.active_colour(name))
    health = strategy.health
    nuk.sh(*nuk.compose_args(name, spec), "--profile", previous, "up", "-d", "--no-recreate")
    nuk.await_healthy(
        nuk._container_name(name, health.service, previous),
        health.path,
        timeout=health.timeout,
        interval=health.interval,
        port=health.port or 8000,
        exec_=nuk.sh,
    )
    nuk.write_ingress(name, ingress, vocab, colour=previous, dialect=nuk.router_dialect(name))
    nuk.record_active_colour(name, previous)


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
    for name in nuk._known_deployments():
        manifest = nuk.load(nuk._manifest_file(name))
        hosts = ",".join(i.host for i in manifest.spec.ingress)
        ps = ",".join(nuk._compose_ps(name, "{{.State}}")) or "-"
        print(f"{name:24} {ps:32} {hosts}")


def _configured_service_image(
    name: str, spec: nuk.Spec, service: str, colour: str | None
) -> str | None:
    """The image reference compose CONFIGURES for `service`, or None if unresolvable.

    Resolved per service, with the colour's profile enabled: a blue-green
    deployment's services sit behind colour profiles, so a profile-less
    `config --images` lists only the profile-less ones (and in no stable order).
    """
    profile = ["--profile", colour] if colour else []
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*nuk.compose_args(name, spec), *profile, "config", "--format", "json"],
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
    name: str, spec: nuk.Spec, service: str, colour: str | None = None
) -> str | None:
    """Digest of the image the compose file CONFIGURES for `service`, or None.

    `docker compose images` reports the RUNNING containers — the previous release
    before a rollout — so it cannot answer "is this a new rollout"; the configured
    reference is the new tree's. A digest-pinned reference (`repo@sha256:...`) is
    its own identity and needs no daemon lookup (or local image); a tag resolves
    through the daemon's RepoDigests.
    """
    image = nuk._configured_service_image(name, spec, service, colour)
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


def _rollout_key(
    name: str, spec: nuk.Spec, migrate: nuk.Migrate, strategy: nuk.Strategy | None
) -> str | None:
    """The key a rollout is compared by: the migrate service's image digest, else the revision.

    The converge loop re-applies every cycle, so `spec.migrate` must key off what
    actually changes on a new rollout — the image of the very service the
    migration runs in (`_migrate_service`), resolved under the idle colour's
    profile like the migration itself. `None` means neither resolved: the caller
    re-runs the (idempotent) migration rather than recording a sentinel that would
    collide across releases.
    """
    service = nuk._migrate_service(name, migrate, strategy)
    digest = nuk._configured_image_digest(name, spec, service, nuk._migrate_colour(name, strategy))
    if digest:
        return digest
    revision = nuk._applied_revision(name)
    return None if revision == "-" else revision


def _applied_revision(name: str) -> str:
    """Return the short git revision of an app's checkout, or `-` if unknown.

    Workflow-managed deploys mirror their tree with rsync (no `.git`), so they
    have no local revision to report; `-` is returned rather than shelling out.
    """
    repo = nuk._repo_dir(name)
    if not (repo / ".git").exists():
        return "-"
    return nuk._git_try(repo, "rev-parse", "--short", "HEAD") or "-"


def cmd_status(name: str) -> None:
    """Show one deployment's health, ingress, databases, and source provenance.

    Surfaces, for a single app: container/service state (`docker compose ps`),
    each ingress host with its upstream router health, the provisioned
    postgres/redis with **password-redacted** connection URLs (read back from the
    600 creds file via `nuk.read_db_env`, never the raw secret), and the source
    repo/branch plus the last applied git revision.
    """
    manifest_file = nuk._manifest_file(name)
    if not manifest_file.exists():
        nuk.die(f"nuk: {name}: no such deployment ({manifest_file} not found)")
    manifest = nuk.load(manifest_file)
    source = manifest.spec.source

    ps = nuk._compose_ps(name, "{{.Service}}: {{.State}}")
    print(f"deployment: {name}")
    print("containers:")
    for line in ps or ["(none running)"]:
        print(f"  {line}")

    print("ingress:")
    for ing in manifest.spec.ingress or []:
        exists, healthy = nuk._container_state(f"{name}-{ing.service}-1")
        health = "healthy" if healthy else "unhealthy" if exists else "down"
        print(f"  https://{ing.host} -> {ing.service}:{ing.port} [{health}]")
    if not manifest.spec.ingress:
        print("  (none)")

    print("databases:")
    env = nuk.read_db_env(name)
    db_urls = [
        (kind, nuk._redact_db_url(env.get(key)))
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
    print(f"  revision: {nuk._applied_revision(name)}")


def cmd_status_overview(
    *, pretty: bool, show_all: bool, org_file: Path | None, probe: bool
) -> None:
    """Print the org-wide status Overview as JSON (walks DEPLOYS/*/; see nuk.build_overview).

    Args:
        pretty: Indent the JSON for human scanning; compact (single-line) otherwise.
        show_all: Also emit the `--all` soll-vs-ist block (needs `org_file`).
        org_file: Path to `nuklaut.org.yml`, required when `show_all` is set.
        probe: Best-effort outbound HTTPS probe per ingress host (off by default).
    """
    overview = nuk.build_overview(probe_enabled=probe)
    converge = nuk.read_converge_status()
    if converge is not None:
        overview = replace(overview, converge=converge)
    if show_all:
        overview = nuk._soll_vs_ist(overview, org_file)
    print(json.dumps(overview.to_wire(), indent=2 if pretty else None))


def cmd_logs(name: str) -> None:
    """Follow compose logs for a deployment."""
    manifest = nuk.load(nuk._manifest_file(name))
    nuk.sh(*nuk.compose_args(name, manifest.spec), "logs", "-f")


def cmd_rollout(name: str) -> None:
    """Git pull + compose pull + up -d for a deployment."""
    manifest = nuk.load(nuk._manifest_file(name))
    repo = nuk._repo_dir(name)
    if (repo / ".git").exists():
        nuk.sh("git", "-C", str(repo), "pull", "--ff-only")
    # else: workflow-managed deployment — re-trigger the workflow to update the tree.
    nuk.sh(*nuk.compose_args(name, manifest.spec), "pull")
    nuk.sh(*nuk.compose_args(name, manifest.spec), "up", "-d")


def _pin_image(name: str, spec: nuk.Spec, pin_digest: str) -> None:
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
        ref
        for ref in nuk._compose_images(name, spec)
        if ref.split("@")[0].split(":")[0] == repo_name
    ]
    if not refs:
        nuk.die(
            f"{name}: the pinned compose references no image from {repo_name} — "
            f"cannot pin {pin_digest}"
        )
    nuk.sh("docker", "pull", pin_digest)
    for ref in refs:
        nuk.sh("docker", "tag", pin_digest, ref)


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
    history = nuk.read_provenance_history(name)
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
    manifest = nuk._manifest_file(name)
    if not manifest.exists():
        nuk.die(f"{name}: {manifest} is missing — nothing to re-apply")
    try:
        raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        parsed = nuk.models._MANIFEST_ADAPTER.validate_python(raw)
    except ValidationError as e:
        nuk.die(
            f"{name}: the persisted manifest no longer validates under the current "
            f"schema (a field was removed since; spec §8) — refusing to silently "
            f"upgrade it into the new schema: {e}"
        )
    if parsed.kind != "Deployment":
        nuk.die(
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
        if not nuk._active_colour_file(name).exists():
            # `nuk.active_colour` would default to blue, flipping to a colour that
            # never ran. Refuse instead, mirroring the digest path's wording.
            nuk.die(f"{name}: no previous release recorded — nothing to roll back to")
        # Resolve the vocabulary the same way `cmd_apply` does, from the
        # manifest's tree, so rollback and apply cannot drift. The persisted
        # manifest lives in the deploy state dir, which ships no facilities/, so
        # this falls back to nuk.DEFAULT_ROUTE_VOCAB — the built-in chain that
        # duplicates infra/facilities/basic.yml's `basic -> [auth@file]`, kept in
        # step by test_shipped_facilities_reproduce_the_default_vocabulary. A
        # deployment using a tree-only capability would re-render without it
        # until the next converge cycle corrects it.
        ctx = nuk.TreeContext.for_path(manifest)
        vocab = nuk.route_vocabulary(ctx.facilities) if ctx.facilities else nuk.DEFAULT_ROUTE_VOCAB
        nuk._rollback_blue_green(name, parsed.spec, parsed.spec.ingress, vocab, strategy)
        return
    if to is None and len(history) < 2:  # noqa: PLR2004  # need a current AND a previous
        nuk.die(f"{name}: no previous release recorded — nothing to roll back to")
    index = -2 if to is None else to
    try:
        entry = history[index]
    except IndexError:
        nuk.die(f"{name}: no release at index {to} (history has {len(history)} entries)")
    digest = entry.image_digest
    if not digest:
        nuk.die(
            f"{name}: the release at index {index} has no recorded imageDigest "
            f"(a source-built deploy, or one predating digest resolution) — it cannot "
            f"be re-applied by digest (spec §8). Roll forward, or re-apply its commit by hand."
        )
    commit = entry.commit
    if not commit:
        nuk.die(
            f"{name}: the release at index {index} has no recorded commit "
            f"(a workflow deploy from a .git-less tree) — its compose tree is "
            f"unreproducible, cannot re-apply it"
        )
    print(f"{name}: rolling back to {digest} (applied {entry.applied_at or '?'})")
    nuk.cmd_apply(manifest, None, pin_commit=commit, pin_digest=digest)


def cmd_delete(name: str, purge: bool) -> None:
    """Tear down a deployment, keeping its database unless `purge` is set."""
    pdir = nuk.project_dir(name)
    if (pdir / "manifest.yml").exists():
        manifest = nuk.load(pdir / "manifest.yml")
        subprocess.run([*nuk.compose_args(name, manifest.spec), "down", "-v"], check=False)  # noqa: S603  # argv built from fixed verbs
    nuk._router_file(name).unlink(missing_ok=True)
    shutil.rmtree(pdir, ignore_errors=True)
    # The app's database is kept by default — its creds file (in SECRETS, not
    # pdir) survives rmtree and keeps nuk aware of it (see `nuk db ls`). --purge
    # is the only path that destroys data.
    if purge:
        nuk.purge_databases(name)
    elif nuk._db_env_path(name).exists():
        print(f"{name}: database retained. `nuk db ls` to view, `nuk db purge {name}` to drop it.")


def cmd_db_ls() -> None:
    """List managed databases; flag retained ones with no live deployment."""
    for app in nuk._db_env_apps():
        env = nuk.read_db_env(app)
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
        live = (nuk._manifest_file(app)).exists()
        status = "deployed" if live else "RETAINED (no deployment — nuk db purge to drop)"
        print(f"{app:24} {kinds:16} {status}")


def cmd_db_purge(name: str) -> None:
    """Drop a retained app's database + creds."""
    nuk.purge_databases(name)
    print(f"{name}: database purged.")


# --- shell completion ---------------------------------------------------------


def _known_deployments() -> list[str]:
    """List deployment names (dirs holding a persisted manifest); `cmd_get` iterates these.

    Returns empty (never raises) off the controller, where DEPLOYS is absent, so
    shell completion degrades gracefully.
    """
    if not nuk.paths.DEPLOYS.exists():
        return []
    return sorted(
        p.name for p in nuk.paths.DEPLOYS.iterdir() if p.is_dir() and (p / "manifest.yml").exists()
    )


def complete_deployment_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for deployment-name arguments (logs/rollout/...)."""
    return [n for n in nuk._known_deployments() if n.startswith(incomplete)]


def complete_db_name(incomplete: str) -> list[str]:
    """Dynamic shell completion for `db purge` — retained DB creds in SECRETS.

    Purge targets a database by its creds file, which outlives the deployment
    (see `cmd_db_ls`), so this enumerates SECRETS rather than live deployments.
    """
    return [n for n in nuk._db_env_apps() if n.startswith(incomplete)]


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
