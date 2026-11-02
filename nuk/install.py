#!/usr/bin/env python3
"""`spec.install`: put a facility's file from the verified tag into traefik/dynamic/.

Traefik watches that directory, so a file there must never be seen half-written (a truncate
reads as an empty config and every router goes invalid for a moment). The render is
structure-aware — parse, substitute in values, dump, re-parse — because textual
substitution on YAML is how a multi-line value once cut through the structure
(astrocloud terraform redesign, lesson 1).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from nuk import paths

if TYPE_CHECKING:
    from nuk.models import Install
    from nuk.org import Org

_TOKEN = re.compile(r"__([A-Z][A-Z0-9_]*)__")
_STAGING = ".nuk-staging"
# Traefik reads the file as another user inside its container.
_FILE_MODE = 0o644


def _substitute(node: object, tokens: dict[str, str], missing: set[str]) -> object:
    """Replace tokens in string VALUES of a parsed document; keys are never touched."""
    if isinstance(node, str):

        def sub(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in tokens:
                missing.add(name)
                return match.group(0)
            return tokens[name]

        return _TOKEN.sub(sub, node)
    if isinstance(node, list):
        return [_substitute(v, tokens, missing) for v in node]
    if isinstance(node, dict):
        return {k: _substitute(v, tokens, missing) for k, v in node.items()}
    return node


def render(text: str, tokens: dict[str, str]) -> str:
    """Render a YAML document with `__TOKEN__`s replaced in its values.

    Raises:
        ValueError: If the document is not a mapping, a token has no value, or the
            rendered document does not parse back to what was built (never writes a
            file Traefik would discard).
    """
    doc = yaml.safe_load(text)
    is_mapping = isinstance(doc, dict)
    if not is_mapping:
        msg = "an installed file must be a YAML mapping"
        raise ValueError(msg)
    missing: set[str] = set()
    rendered = _substitute(doc, tokens, missing)
    if missing:
        msg = f"unresolved token(s): {', '.join(sorted(missing))}"
        raise ValueError(msg)
    out = yaml.safe_dump(rendered, sort_keys=False, default_flow_style=False, allow_unicode=True)
    if yaml.safe_load(out) != rendered:
        msg = "the rendered document does not round-trip"
        raise ValueError(msg)
    return out


def _read_secret(token: str, file: str) -> str:
    """The first non-blank line of an allowed secret file.

    Raises:
        ValueError: If the file is outside the secret roots or has no content. The message
            never carries the value.
    """
    path = Path(file).resolve()
    roots = (paths.SECRET_FILES.resolve(), paths.RUN_SECRETS.resolve())
    if not any(path.is_relative_to(root) for root in roots):
        msg = f"secret file for {token} must live under {paths.SECRET_FILES} or {paths.RUN_SECRETS}"
        raise ValueError(msg)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        msg = f"secret file for {token} is unreadable: {e.strerror}"
        raise ValueError(msg) from None
    value = next((ln.strip() for ln in lines if ln.strip()), "")
    if not value:
        msg = f"secret file for {token} is empty"
        raise ValueError(msg)
    return value


def _tokens(item: Install, org: Org | None) -> dict[str, str]:
    tokens = {name: _read_secret(name, file) for name, file in item.secret_vars.items()}
    tokens.update(item.vars)
    if org is not None:
        tokens["DOMAIN"] = org.platform_domain
    return tokens


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def install_file(facility: str, item: Install, payload: Path, org: Org | None) -> bool:
    """Render `item.src` from `payload` and install it atomically; True if the file changed.

    A destination nuk did not write (no recorded hash, or content differing from it) is
    refused, never overwritten: it may be the cloud-init copy of a fleet host or a hand-made
    file. One that already equals the render is adopted.

    Raises:
        ValueError: On a source outside the payload, an unrenderable file, or a destination
            nuk does not own. Nothing is written in any of those cases.
        OSError: If the atomic swap itself fails; the old file is untouched.
    """
    src = (payload / item.src).resolve()
    if not src.is_relative_to(payload.resolve()):
        msg = f"install src {item.src!r} resolves outside the payload"
        raise ValueError(msg)
    try:
        text = src.read_text(encoding="utf-8")
    except OSError as e:
        msg = f"install src {item.src!r}: {e.strerror}"
        raise ValueError(msg) from None
    data = render(text, _tokens(item, org)).encode("utf-8")
    dest = paths.DYNAMIC / item.name
    stamp = paths.INSTALLED / f"{facility}--{item.name}.sha256"
    new = _sha(data)
    if dest.exists():
        current = _sha(dest.read_bytes())
        known = stamp.read_text(encoding="utf-8").strip() if stamp.exists() else None
        if current not in {new, known}:
            msg = (
                f"{dest} was not written by nuk (or was edited since); refusing to overwrite. "
                f"Move it aside once to hand it over:  mv {dest} {dest}.pre-nuk"
            )
            raise ValueError(msg)
        if current == new:
            _record(stamp, new)
            return False
    _swap(dest, data)
    _record(stamp, new)
    return True


def _record(stamp: Path, digest: str) -> None:
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(digest + "\n", encoding="utf-8")


def _swap(dest: Path, data: bytes) -> None:
    """Write `data` beside the watched directory, then rename it over `dest` in one step."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = dest.parent.parent / _STAGING  # same filesystem, outside what Traefik watches
    staging.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=staging, prefix=f"{dest.name}.")
    tmp = Path(name)
    try:
        _write_synced(fd, data)
        tmp.chmod(_FILE_MODE)
        tmp.replace(dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _write_synced(fd: int, data: bytes) -> None:
    """Write and fsync, so the rename publishes bytes that are on disk."""
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
