#!/usr/bin/env python3
"""Convergence loop: apply, convergence cycle, status views dependent bits."""

from __future__ import annotations

import fcntl
import io
import json
import os
import sys
import tarfile
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path  # noqa: TC003

import nuk
from nuk.models import ValidationError  # noqa: TC003
from nuk.records import ConvergeStatus  # noqa: TC003
from nuk.util import NukError  # noqa: TC003

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
    archive = nuk.subprocess.run(  # noqa: S603  # fixed argv, no shell
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


def _provided_capabilities(manifest: nuk.Facility) -> set[str]:
    """The capabilities a nuk.Facility hands out (its `provides` block)."""
    provides = manifest.spec.provides
    return {p.capability for p in (provides.route, provides.env) if p is not None}


def provision_remote_databases(
    tree: Path,
    role: str,
    facilities: list[nuk.Facility],
    *,
    self_ip: str | None = None,
    org: nuk.Org | None = None,
) -> list[nuk.ManifestResult]:
    """Provision every deployment's databases on this host IF it owns the capability.

    The placement-gate exception (spec §3.1): a deployment placed `app` is a
    no-op on the `data` host for containers and ingress, but its `spec.databases`
    fragment must still be provisioned HERE — this is the only host with a local
    `nuk-postgres`. Scoped to provisioning: nothing else about the manifest runs.

    Deterministic derivation makes this loop-stable: the same seed yields the
    same password, so re-running converges to a no-op rather than rotating.
    """
    provider = nuk.env_facility(facilities, nuk._DATABASES_CAPABILITY)
    if provider is None or not placement_matches(provider, role, self_ip=self_ip, org=org):
        return []
    out: list[nuk.ManifestResult] = []
    for path in sorted((tree / nuk.DEPLOYMENT_DIR).glob("*.yml")):
        try:
            manifest = nuk.load(path)
        except SystemExit as e:
            out.append(
                nuk.ManifestResult(
                    path.name, "Database", "failed", _exit_reason(e, "nuk.load failed")
                )
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
            nuk.provision_databases(name, dbs, facilities, remote_ip=None)
        except (SystemExit, nuk.subprocess.CalledProcessError) as e:
            # One app's provisioning failure must not abort the cycle (spec §7.5):
            # `_psql` uses check=True, so a SQL failure (disk full, role/db
            # conflict, container hiccup) surfaces as CalledProcessError, not
            # SystemExit. The data host still writes converge-status.json.
            error = (
                _exit_reason(e, "provision failed")
                if isinstance(e, SystemExit)
                else f"provision failed: {e}"
            )
            out.append(nuk.ManifestResult(name, "Database", "failed", error))
            if dbs.postgres_scratch:
                out.append(nuk.ManifestResult(f"{name}-scratch", "Database", "failed", error))
            continue
        out.append(nuk.ManifestResult(name, "Database"))
        if dbs.postgres_scratch:
            out.append(nuk.ManifestResult(f"{name}-scratch", "Database"))
    return out


def _exit_reason(e: SystemExit, default: str) -> str:
    """The message a SystemExit carried, or `default` for a bare exit."""
    return str(e.code) if e.code else default


def _deployment_tree(ctx: nuk.TreeContext, manifest: nuk.Deployment, path: Path) -> Path:
    """The tree one nuk.Deployment applies from (Task 11).

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


def apply_tree(ctx: nuk.TreeContext) -> list[nuk.ManifestResult]:  # noqa: C901  # placement ambiguity is recorded per manifest, not raised out of the loop
    """Apply this host's Facilities, then its Deployments (spec §7 steps 6-7).

    Facilities first within a cycle (§7.1): effect VOCABULARY is git-derived and
    always resolvable regardless of order, but facility HEALTH needs the facility
    up, and that is same-host. Cross-host ordering is eventual and covered by
    `maintenance-errors@file`.

    One failing manifest never stops the rest (§7.5). `nuk.cmd_apply` and `nuk.load` both
    signal failure with SystemExit, so each manifest is isolated and its message
    recorded for the status file — a malformed manifest must not take down the
    cycle for every other manifest on the host.

    A facility that fails this cycle POISONS the capabilities it declares:
    a nuk.Deployment whose static `consumes()` (§5.3) intersects them is recorded
    "refused" and never applied (§7.5: "Deployments consuming it refuse"). A
    facility placed on another host is skipped before it can fail, and this host
    cannot verify another host's liveness (§13) — only same-host failures refuse.

    Only the kinds named in `ctx.apply` run: a tenant source's `facilities/` is
    never looked at, whatever it contains.

    Args:
        ctx: The source's tree, this host's identity and what the source may change.

    Returns:
        One nuk.ManifestResult per manifest this host owns, facilities first, each
        directory in filename order. `result` is "ok", "failed", or "refused".
    """
    tree, role = ctx.tree, ctx.role
    results: list[nuk.ManifestResult] = []
    failed_caps: set[str] = set()
    kinds: tuple[tuple[nuk.ManifestKind, str], ...] = (
        ("Facility", nuk.FACILITY_DIR),
        ("Deployment", nuk.DEPLOYMENT_DIR),
    )
    for kind, directory in kinds:
        if directory not in ctx.apply:
            continue
        for path in sorted((tree / directory).glob("*.yml")):
            try:
                manifest = nuk.load(path)
            except SystemExit as e:
                results.append(
                    nuk.ManifestResult(
                        path.name, kind, "failed", _exit_reason(e, "nuk.load failed")
                    )
                )
                continue
            if manifest.kind != kind:
                continue
            try:
                matches = placement_matches(manifest, role, self_ip=ctx.self_ip, org=ctx.org)
            except ValueError as e:
                results.append(nuk.ManifestResult(manifest.metadata.name, kind, "failed", str(e)))
                continue
            if not matches:
                continue
            apply_path = path
            if isinstance(manifest, nuk.Deployment):
                poisoned = consumes(manifest) & failed_caps
                if poisoned:
                    reason = (
                        f"consumes {sorted(poisoned)} from a facility that "
                        f"failed its health gate this cycle (spec §7.5)"
                    )
                    results.append(
                        nuk.ManifestResult(manifest.metadata.name, kind, "refused", reason)
                    )
                    continue
                apply_path = _deployment_tree(ctx, manifest, path)
            # A signed (non-unsigned) deployment must BUILD the signed tag, not the
            # branch head its clone would otherwise follow: pin the clone to the
            # tag commit. An unsigned deployment stays on the branch head. A context
            # without a recorded tag commit (hand-run `for_path`, or Task 10's
            # `build()` asymmetry with `commits={}`) degrades to today's behaviour —
            # no pin — rather than raising. (`nuk.cmd_apply` refuses a TENANT deployment
            # whose payload repo is not the source's own, so this pin always has the
            # commit it names: a tenant ships its payload in its own repo or in the
            # tree.)
            pin_commit = (
                ctx.commits.get("tag")
                if isinstance(manifest, nuk.Deployment) and not manifest.spec.source.unsigned
                else None
            )
            try:
                nuk.cmd_apply(apply_path, None, ctx=ctx, pin_commit=pin_commit)
            except (SystemExit, ValueError, nuk.subprocess.CalledProcessError, OSError) as e:
                error = _exit_reason(e, "apply failed") if isinstance(e, SystemExit) else str(e)
                results.append(nuk.ManifestResult(manifest.metadata.name, kind, "failed", error))
                if isinstance(manifest, nuk.Facility):
                    failed_caps |= _provided_capabilities(manifest)
                continue
            results.append(nuk.ManifestResult(manifest.metadata.name, kind))
    # The placement exception (spec §3.1) runs in addition to the filter above: a
    # `{placement: app}` deployment is a container/ingress no-op here but its
    # `spec.databases` fragment is still this host's job when it owns the
    # facility. A deployment the loop already produced (applied, refused, failed)
    # was provisioned by `nuk.cmd_apply` itself — the sweep must not double it.
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
    for directory in (nuk.FACILITY_DIR, nuk.DEPLOYMENT_DIR):
        for path in (tree / directory).glob("*.yml"):
            raw = nuk._read_yaml_safe(path)
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
    if not nuk.paths.DEPLOYS.is_dir():
        return []
    declared: set[str] = set()
    for tree in trees:
        declared |= _declared_names(tree)
    return sorted(
        p.name for p in nuk.paths.DEPLOYS.iterdir() if p.is_dir() and p.name not in declared
    )


def write_converge_status(  # noqa: PLR0913  # one status field per keyword; a dataclass buys nothing here
    path: Path,
    *,
    role: str,
    tenant: str | None,
    sources: dict[str, nuk.SourceBlock],
    warnings: list[str],
    logging: nuk.LoggingStatus | None = None,
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
        applied_at=nuk._iso_utc_now(),
        reap_warnings=warnings,
        sources=sources,
        logging=logging,
        error=error,
    )
    nuk._atomic_write(path, json.dumps(status.to_wire(), indent=2) + "\n")


def read_converge_status(path: Path | None = None) -> ConvergeStatus | None:
    """The last recorded cycle, or None if absent/unreadable/malformed."""
    if path is None:
        path = nuk.paths.CONVERGE_STATUS
    return ConvergeStatus.from_wire(nuk._read_json_safe(path))


_SOURCE_FAILURES = (ValueError, SystemExit, nuk.subprocess.CalledProcessError, OSError)


def _prepare_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: nuk.SourceEntry,
    block: nuk.SourceBlock,
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
    scratch: Path,
    platform: Path | None,
) -> nuk.TreeContext:
    """Sync, verify and archive one source and build its context; fill tag/commit/verify in `block`.

    Both refs are archived: the signed tag's tree under `tag` and the branch head's
    under `branch`. `ctx.tree` remains the tag tree (what a signed deployment
    applies); Task 11's per-deployment selection reads `ctx.trees`. Only the tag
    path is downgrade-guarded (`nuk.sync_source`).

    Raises:
        ValueError: With the refusal reason (also CalledProcessError/OSError/SystemExit from
            the git and manifest layers — `_SOURCE_FAILURES`).
    """
    block.verify = src.verify
    if not src.is_platform and platform is None:
        msg = (
            "the platform source did not verify this cycle — no facilities or org to apply against"
        )
        raise ValueError(msg)
    tag, tag_sha, branch_sha = nuk.sync_source(src, signers_dir, state_dir)
    block.tag, block.commit = tag, tag_sha
    if src.verify == "none":
        print(f"target: {src.name} {tag} ({tag_sha[:12]}) UNVERIFIED")
    else:
        print(f"target: {src.name} {tag} ({tag_sha[:12]}) role={role}")
    repo = nuk.source_state_dir(state_dir, src.name) / "repo"
    tag_tree = scratch / src.name / "tag"
    branch_tree = scratch / src.name / "branch"
    archive_tree(repo, tag_sha, tag_tree)
    archive_tree(repo, branch_sha, branch_tree)
    tenant = None if src.is_platform else src.name
    return nuk.TreeContext.build(
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
    src: nuk.SourceEntry,
    ctx: nuk.TreeContext,
    block: nuk.SourceBlock,
    state_dir: Path,
    auth: nuk.HostAuth,
) -> None:
    """Apply a prepared source: manifests, then routes; record it applied only if all went well."""
    block.manifests = apply_tree(ctx)
    if "routes" in src.apply and ctx.role in nuk._ENTRY_ROLES:
        routes = render_routes(ctx, auth)
        block.rendered = routes.rendered
        block.refused_routes = routes.refused
    # _prepare_source always sets both before a source reaches the apply pass.
    assert block.tag is not None  # noqa: S101  # narrows the union for ty
    assert block.commit is not None  # noqa: S101  # narrows the union for ty
    nuk.record_applied(
        block.tag, block.commit, nuk.source_state_dir(state_dir, src.name) / "last-applied-tag"
    )


def _refuse(src: nuk.SourceEntry, block: nuk.SourceBlock, e: BaseException) -> None:
    block.result = "refused"
    block.error = _exit_reason(e, "converge refused") if isinstance(e, SystemExit) else str(e)
    print(f"REFUSING source {src.name}: {block.error}", file=sys.stderr)


def _converge_source(  # noqa: PLR0913  # one keyword per cycle input; they are all read, none derived
    src: nuk.SourceEntry,
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
    scratch: Path,
    platform: Path | None,
) -> tuple[nuk.SourceBlock, nuk.TreeContext | None]:
    """PREPARE one source (sync/verify/archive); never raises for a source-level failure.

    The apply step moved to `_run_cycle`'s second pass so every source's tree is known
    before any renders (a delegation must be honoured in the cycle it lands, spec §3.5).

    Returns:
        The source's status block, and its nuk.TreeContext once the tree is verified and archived
        (None when that failed, or when the platform tree is incomplete) — the platform's
        context is what tenant sources build on. `result` is "refused" on any failure here.
    """
    block = nuk.SourceBlock(apply=[str(a) for a in src.apply])
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
                f"the platform tree at {block.tag} lacks {nuk.DEFAULT_ORG_FILE} — "
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
    prepared: list[tuple[nuk.SourceEntry, nuk.TreeContext]],
    *,
    blocks: dict[str, nuk.SourceBlock],
) -> tuple[dict[str, list[nuk.Delegation]], list[tuple[nuk.SourceEntry, nuk.TreeContext]]]:
    """Load each routable prepared owner's `delegations.yml`, refusing a malformed one (spec §2).

    Only sources with `routes` in `apply` contribute (spec §2). A malformed manifest is
    attributable, so it refuses THAT source alone: its loans are never added to the returned
    map, it drops out of the caller's authorization set, and the rest of the fleet proceeds.

    Returns:
        The owner loans loaded so far and the prepared sources still in play.
    """
    delegations: dict[str, list[nuk.Delegation]] = {}
    keep: list[tuple[nuk.SourceEntry, nuk.TreeContext]] = []
    for src, ctx in prepared:
        if ctx.tenant is None or "routes" not in src.apply:
            keep.append((src, ctx))
            continue
        try:
            delegations[ctx.tenant] = nuk.load_delegations(ctx.tree)
        except _SOURCE_FAILURES as e:
            _refuse(src, blocks[src.name], e)
            continue
        keep.append((src, ctx))
    return delegations, keep


def _cached_delegations(state_dir: Path, owner: str) -> list[nuk.Delegation]:
    """`owner`'s last-verified loans; a corrupt cache is a recorded cycle failure (spec §4).

    A refused owner lends its cache so a foreign fetch failure cannot pull a lent name away.
    If that cache is unreadable the loan set is UNKNOWN — dropping it would silently withdraw
    lent names — so this raises `_UnknownAuthorizationError` (carrying the reason) for the caller
    to record, rather than degrading to an empty loan set.
    """
    try:
        return nuk.load_cached_delegations(state_dir, owner)
    except NukError as e:
        raise _UnknownAuthorizationError(_exit_reason(e, "cached delegations unreadable")) from e


def _refuse_bad_declarations(
    prepared: list[tuple[nuk.SourceEntry, nuk.TreeContext]],
    refused: list[nuk.SourceEntry],
    registry: nuk.TenantRegistry,
    delegations: dict[str, list[nuk.Delegation]],
    *,
    blocks: dict[str, nuk.SourceBlock],
) -> list[tuple[nuk.SourceEntry, nuk.TreeContext]]:
    """Refuse each source whose declarations do not validate; return the survivors.

    `nuk.validate_delegations` and `nuk.check_cross_zone_patterns` judge one tenant at a time, so
    a violation refuses THAT source — its loans are dropped from `delegations` and the rest
    of the fleet proceeds — instead of aborting the whole cycle (spec §2). A loan judged
    against a bad declaration is therefore never honoured, so fail-closed holds. An
    already-refused source whose cached loan is invalid is simply not honoured, never a
    second refusal.
    """
    surviving: list[tuple[nuk.SourceEntry, nuk.TreeContext]] = []
    for src, ctx in prepared:
        if ctx.tenant is None:
            surviving.append((src, ctx))
            continue
        dels = delegations.get(ctx.tenant, [])
        try:
            if dels:
                nuk.validate_delegations(ctx.tenant, dels, registry)
            nuk.check_cross_zone_patterns(ctx.tenant, registry, delegations)
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
            nuk.validate_delegations(src.name, dels, registry)
        except _SOURCE_FAILURES:
            delegations.pop(src.name, None)
    return surviving


def _host_auth(
    platform_ctx: nuk.TreeContext | None,
    prepared: list[tuple[nuk.SourceEntry, nuk.TreeContext]],
    *,
    state_dir: Path,
    refused: list[nuk.SourceEntry],
    blocks: dict[str, nuk.SourceBlock],
) -> tuple[nuk.HostAuth, list[tuple[nuk.SourceEntry, nuk.TreeContext]]]:
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
        registry = nuk.TenantRegistry(tenants=[])
    delegations, prepared_ok = _load_prepared_delegations(prepared, blocks=blocks)
    for src in refused:
        # Without a verified platform tree there is no registry to authorize against, so
        # the cache would add nothing but a spurious "not in the registry" refusal.
        if not src.is_platform and "routes" in src.apply and platform_ctx is not None:
            delegations[src.name] = _cached_delegations(state_dir, src.name)
    surviving = _refuse_bad_declarations(prepared_ok, refused, registry, delegations, blocks=blocks)
    for src, ctx in surviving:
        if ctx.tenant is not None and "routes" in src.apply:
            nuk.store_delegations(state_dir, ctx.tenant, delegations[ctx.tenant])
    return nuk.HostAuth(registry, delegations), surviving


def _logging_status(role: str, platform_ctx: nuk.TreeContext | None) -> nuk.LoggingStatus | None:
    """The LOGGING pipeline's own health (spec §14.3): info-only, edge cycles only."""
    if role != "edge" or platform_ctx is None:
        return None
    facility = nuk.env_facility(platform_ctx.facilities, "logs")
    if facility is None:
        return None
    reason = nuk.facility_health(facility)
    return nuk.LoggingStatus(healthy=reason is None, detail=reason or "ok")


def _run_cycle(  # noqa: PLR0913  # one keyword per cycle input
    sources: list[nuk.SourceEntry],
    blocks: dict[str, nuk.SourceBlock],
    *,
    role: str,
    self_ip: str | None,
    signers_dir: Path,
    state_dir: Path,
) -> tuple[list[str], nuk.LoggingStatus | None, bool, str | None]:
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
        prepared: list[tuple[nuk.SourceEntry, nuk.TreeContext]] = []
        refused: list[nuk.SourceEntry] = []
        platform_ctx: nuk.TreeContext | None = None
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
        auth: nuk.HostAuth | None = None
        applied: list[tuple[nuk.SourceEntry, nuk.TreeContext]] = []
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
        warnings = nuk.reap_report(*trees) if clean else []
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
        role, self_ip = nuk.read_self()
        blocks: dict[str, nuk.SourceBlock] = {}
        warnings: list[str] = []
        logging_status: nuk.LoggingStatus | None = None
        error: str | None = None
        code = 1
        sources: list[nuk.SourceEntry] = []
        try:
            sources = nuk.load_sources(sources_file).ordered()
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
                tenant=nuk.read_tenant(),
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
    manifest: nuk.Deployment | nuk.Facility,
    role: str,
    *,
    self_ip: str | None = None,
    org: nuk.Org | None = None,
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
    is a loud error. A nuk.Deployment placed `app` with no `host` resolves to the org's
    default app host once the org has more than one app host; without a default it
    is a loud error, never a silent double-deploy. A nuk.Facility is shared substrate
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
    if isinstance(manifest, nuk.Deployment) and role == "app" and org is not None:
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
    org: nuk.Org,
    *,
    tenant: str | None,
    auth: nuk.HostAuth | None,
    platform_facilities: list[nuk.Facility] | None = None,
) -> nuk.RouteResult:
    """On the edge: render a router for EVERY nuk.Deployment with ingress (spec §6).

    Cross-host router delivery is gone. The edge reads the same git tree every
    host reads and resolves each backend from the org manifest, so the app host
    authors nothing that reaches the edge (spec §6, §6.3).

    Stale routers for retired apps are NOT removed here — a manifest disappearing
    from git is destructive, and the loop reports rather than deletes (spec §7.4).
    The one bounded exception is the legacy `worker-` prefix (nuk.reap_legacy_worker_routers).

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
    nuk.paths.DYNAMIC.mkdir(parents=True, exist_ok=True)
    deployments = nuk.load_deployments(tree)
    protected = {f"{m.metadata.name}.yml" for m in deployments}
    for stale in nuk.reap_legacy_worker_routers(protected):
        print(f"edge: reaped legacy router {stale} (cross-host delivery is retired)")
    facilities = nuk.load_facilities(tree)
    vocab = nuk.route_vocabulary(facilities)
    router_present = nuk._router_present(platform_facilities or facilities)
    rendered: list[str] = []
    refused: list[str] = []
    for manifest in deployments:
        ingress = manifest.spec.ingress
        if not ingress:
            continue
        # A deployment placed on an entry host runs ALONGSIDE Traefik, so
        # nuk.cmd_apply already rendered its router there with a container-name
        # backend. Re-rendering it from here would overwrite that working file
        # with a `privateIp:port` backend nothing is listening on.
        placement = manifest.spec.placement
        if placement is not None and placement.role in nuk._ENTRY_ROLES:
            continue
        if tenant is not None:
            allowed = nuk._authorized_ingress(ingress, tenant, auth, refused)
            if not allowed:
                # Revocation (spec §5): the owner's router set is authoritative, so a
                # render that allows none of the deployment's hosts withdraws the file
                # it wrote before. The withdrawal is keyed by the deployment's name, so a
                # fleet-wide name collision would touch another source's router — the
                # system discourages that, but this path does not detect it.
                nuk.write_ingress(manifest.metadata.name, [], vocab)
                continue
            ingress = allowed
        # Fronted by the app-host router (backend_address's rule): that router strips
        # `path` itself, so stripping here too sends `/api/x` on as `/x`, past every
        # PathPrefix router there, into the catch-all. Only the last hop may strip.
        fronted = router_present and placement is not None and placement.role == "app"
        resolved = [
            ing.model_copy(
                update={
                    "address": nuk.backend_address(
                        org, manifest, ing, router_present=router_present
                    ),
                    "service": None,
                    "port": None,
                    "host_port": None,
                    "strip_prefix": ing.strip_prefix and not (fronted and not ing.address),
                }
            )
            for ing in ingress
        ]
        name = manifest.metadata.name
        nuk.write_ingress(name, resolved, vocab)
        rendered.append(name)
    return nuk.RouteResult(rendered, refused)


def render_routes(ctx: nuk.TreeContext, auth: nuk.HostAuth | None = None) -> nuk.RouteResult:
    """On the edge: render ONE source's routers through the host authorization (spec §3).

    The platform source (ctx.tenant is None) is unconstrained — it owns the platform
    domains. A tenant source renders only the hosts `auth` names as its own; without an
    authorization it renders nothing (fail-closed).
    """
    if ctx.org is None:
        return nuk.RouteResult([], [])
    return _render_routers(
        ctx.tree,
        ctx.org,
        tenant=ctx.tenant,
        auth=auth,
        platform_facilities=ctx.facilities,
    )


def consumes(manifest: nuk.Deployment) -> set[str]:
    """The capabilities this nuk.Deployment consumes, derived from its own fields.

    Static consumption (spec §5.3) — the map is a literal lookup, and adding a
    capability adds a row:

    | nuk.Deployment field        | Consumes                   |
    |--------------------------|----------------------------|
    | `databases:`            | env capability `databases` |

    A nuk.Deployment consuming nothing still gets the default `tls` route from the
    ingress facility; `tls` is substrate, not consumption. Plan 3's loop uses
    this to refuse the consumers of a facility that failed its health gate
    (§7.5) without any runtime state.

    Args:
        manifest: The nuk.Deployment being considered.

    Returns:
        The capability names consumed; empty for none.
    """
    caps: set[str] = set()
    db = manifest.spec.databases
    if db.postgres or db.redis:
        caps.add(nuk._DATABASES_CAPABILITY)
    return caps
