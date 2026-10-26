#!/usr/bin/env python3
"""Signed-tag trust and sources contract (contracts C3).

Extracted from `nuk/__init__` during the module split.
"""

from __future__ import annotations

import os
import shlex
import subprocess  # noqa: S404
import sys
from pathlib import Path  # noqa: TC003
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from nuk import paths
from nuk.util import (
    _git,
    _is_ancestor,
)

# --- signed-tag trust ----------------------------------------------------------
# Ported from infra/tf-incus/reconcile.sh:74-120, which guards the LAYER-1 loop
# (terraform, nuroot only, bash). This is the LAYER-3 loop (nuk manifests, every
# platform host, Python). The logic is duplicated on purpose — sharing it would
# mean shipping bash into nuk or terraform onto the fleet — so keep the two in
# step: a fix to either belongs in both. Both bugs the bash version grew during
# host verification (2026-08-15) are re-encoded as tests here.


def _verify(repo: Path, signers: Path, tag: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # fixed argv, no shell
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
        text=True,
    )


def verify_tag(repo: Path, signers: Path, tag: str) -> bool:
    """Whether `tag`'s signature verifies against the allowed-signers file.

    `gpg.format=ssh` and the signers file are passed with `-c` rather than read
    from the repo's own config: a repo that names its own trust anchor does not
    have one.
    """
    return _verify(repo, signers, tag).returncode == 0


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

    Skipping is silent to the loop but never to the operator: every rejected tag
    the result does not already contain is reported on stderr with git's reason,
    because a release signed with the wrong key otherwise just never lands.
    """
    try:
        refs = _git(
            repo, "for-each-ref", "--sort=-creatordate", "--format=%(refname:short)", "refs/tags/v*"
        ).splitlines()
    except subprocess.CalledProcessError:
        return None
    best: str | None = None
    rejected: list[tuple[str, str]] = []
    for tag in (t.strip() for t in refs if t.strip()):
        proc = _verify(repo, signers, tag)
        if proc.returncode != 0:
            reason = (proc.stderr.strip().splitlines() or [f"exit {proc.returncode}"])[-1]
            rejected.append((tag, reason))
            continue
        if best is None:
            best = tag
            continue
        if _is_ancestor(repo, f"{best}^{{commit}}", f"{tag}^{{commit}}") and not _is_ancestor(
            repo, f"{tag}^{{commit}}", f"{best}^{{commit}}"
        ):
            best = tag
    for tag, reason in rejected:
        if best is None or not _is_ancestor(repo, f"{tag}^{{commit}}", f"{best}^{{commit}}"):
            print(
                f"IGNORING tag {tag} in {repo}: signature does not verify against {signers} "
                f"({reason}) — it will NOT deploy; applying {best or 'nothing'} instead",
                file=sys.stderr,
            )
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
    verify: Literal["signed", "none"] = "signed"

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
        # The platform source's tag is the root of the fleet's trust: a tenant may
        # accept unsigned tags for its own tree, but an unsigned platform tag would
        # let anyone who can push to that repo define what every host applies.
        if platform[0].verify != "signed":
            msg = (
                f"the platform source {platform[0].name} must be signed "
                f"(verify: signed), not verify: {platform[0].verify}"
            )
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
        f"-o UserKnownHostsFile={shlex.quote(str(paths.KNOWN_HOSTS))} -o BatchMode=yes"
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
        # `SOURCE_BRANCH` is hardcoded, and the branch refspec shares ONE fetch with the
        # signed tags: a remote whose branch is not `main` fails the WHOLE fetch, so its
        # valid signed tag can never deploy. Probe for the branch to name the actual
        # reason instead of an opaque `git fetch failed` (per-source/per-deployment
        # branches are a future follow-up — this only tells the operator why the source
        # is refused). Only reached on failure, so a healthy source pays nothing.
        probe = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [  # noqa: S607  # git on PATH
                "git",
                "-C",
                str(repo),
                "ls-remote",
                "--heads",
                "origin",
                f"refs/heads/{SOURCE_BRANCH}",
            ],
            env={**os.environ, "GIT_SSH_COMMAND": git_ssh_command(src.deploy_key)},
            check=False,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0 and not probe.stdout.strip():
            msg = (
                f"{src.name}: origin has no {SOURCE_BRANCH} branch — nuk fetches "
                f"refs/heads/{SOURCE_BRANCH} for every source, so its signed tags cannot "
                f"deploy (per-source branches are a future follow-up)"
            )
            raise ValueError(msg)
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
