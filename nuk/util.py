#!/usr/bin/env python3
"""Generic helpers: process, git, time, IO and wire coercion.

Everything a domain module is allowed to depend on without depending on another
domain module. Nothing here imports a nuk module other than `nuk.paths`, so this
sits at the bottom of the import graph.
"""

from __future__ import annotations

import json
import os
import re
import subprocess  # noqa: S404  # all calls use fixed argv, no shell (see per-call S603/S607)
from datetime import UTC, datetime
from typing import TYPE_CHECKING, NoReturn

import yaml

if TYPE_CHECKING:
    from pathlib import Path


class NukError(SystemExit):
    """A refusal nuk surfaces to the operator: message to stderr, exit status 1.

    Subclasses SystemExit so the one-process-exit contract (and every caller that
    already treats a refusal as an exit) is unchanged, while giving raise sites a
    named type that handlers can catch without also swallowing a stray sys.exit.
    """


def die(message: str) -> NoReturn:
    """Refuse with `message`: the single raise point for operator-facing failures."""
    raise NukError(message)


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _str_list(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _int_or_none(value: object) -> int | None:
    # bool is an int subclass; `port: true` is not a port.
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def sh(
    *cmd: str,
    cwd: Path | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> None:
    """Run a command, raising on non-zero exit (or on `timeout`).

    `env` replaces the child's environment entirely; `None` inherits ours.
    """
    subprocess.run(cmd, cwd=cwd, check=True, timeout=timeout, env=env)  # noqa: S603  # fixed argv


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


def _full_commit_sha(repo_dir: Path) -> str | None:
    """Full HEAD sha of `repo_dir`'s checkout, or None if unavailable."""
    return _git_try(repo_dir, "rev-parse", "HEAD")


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


def _atomic_write(path: Path, text: str) -> None:
    """Write `text` so a reader never sees a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o644)
    tmp.replace(path)


def _read_yaml_safe(path: Path) -> object:
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
        NukError: When the identifier does not match `[a-z][a-z0-9_-]*`.
    """
    if not _IDENT.match(name):
        die(f"nuk: {name!r} is not a valid database identifier ([a-z][a-z0-9_-]*)")
    return name


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


def _iso_utc_now() -> str:
    """Current time as an ISO-8601 UTC timestamp with a `Z` suffix."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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
