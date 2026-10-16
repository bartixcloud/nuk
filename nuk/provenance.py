#!/usr/bin/env python3
"""Provenance / release history: releases/<name>.jsonl."""

from __future__ import annotations

import json
import subprocess  # noqa: S404
import urllib.request
from pathlib import Path  # noqa: TC003

import nuk
from nuk.util import _iso_utc_now, _read_json_safe

# target cannot meaningfully scan past a few dozen entries. Combined with the
# same-release refresh below, 20 is effectively "every recent release".
RELEASE_LIMIT = 20

# /var/lib/nuk is the loop's state dir (CONVERGE_STATE, Task 3). releases/ is
# created by cloud-init and install_converge (Task 7) and defensively here, so a
# hand-run `sudo nuk apply` on a pre-loop host still records (spec §8: survives
# VM rebuild by living on the host's data volume).


def _provenance_path(name: str) -> Path:
    """On-disk path of an app's provenance record."""
    return nuk.project_dir(name) / "provenance.json"


def _releases_path(name: str) -> Path:
    """On-disk path of an app's release history (spec §8)."""
    return nuk.paths.RELEASES / f"{name}.jsonl"


def read_provenance_history(name: str) -> list[nuk.ReleaseEntry]:
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
            return [nuk.ReleaseEntry.from_wire(data)]
        if isinstance(data, list):
            return [nuk.ReleaseEntry.from_wire(e) for e in data if isinstance(e, dict)]
        return []
    entries: list[nuk.ReleaseEntry] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(nuk.ReleaseEntry.from_wire(entry))
    return entries


def read_provenance(name: str) -> nuk.ReleaseEntry | None:
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
    entry = nuk.ReleaseEntry(
        repo=repo,
        branch=branch,
        commit=commit,
        image_digest=image_digest,
        applied_at=_iso_utc_now(),
    )
    history = read_provenance_history(name)
    if history and history[-1].same_release(entry):
        history[-1] = entry
    else:
        history.append(entry)
    nuk.paths.RELEASES.mkdir(parents=True, exist_ok=True)
    _releases_path(name).write_text(
        "".join(json.dumps(e.to_wire()) + "\n" for e in history[-RELEASE_LIMIT:]),
        encoding="utf-8",
    )


def latest_release_tag(repo: str = "astrojones/nuk") -> str | None:
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
