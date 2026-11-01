#!/usr/bin/env python3
"""Decrypt `envFrom[].sopsFile` entries into tmpfs.

The plaintext lives only under ``paths.RUN_SECRETS/<deployment>/`` (0700 dir, 0600
files) and is handed to compose as ``--env-file``. Every failure raises
:class:`SecretError` before anything is rolled out; messages never carry plaintext.
"""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404  # runs sops with a fixed argv
from typing import TYPE_CHECKING

from nuk import paths

if TYPE_CHECKING:
    from pathlib import Path

    from nuk.models import EnvFrom

_SUFFIX = ".enc.env"
_STDERR_LIMIT = 200


class SecretError(Exception):
    """A sops secret could not be rendered; the apply must be refused."""


def _err(rel: str, why: str) -> SecretError:
    return SecretError(f"{rel}: {why}")


def key_name(tenant: str | None) -> str:
    """The age identity name for a source: the tenant, or `platform`."""
    return tenant or "platform"


def purge(name: str) -> None:
    """Remove a deployment's rendered plaintext."""
    shutil.rmtree(paths.RUN_SECRETS / name, ignore_errors=True)


def _resolve(tree: Path, rel: str) -> Path:
    root = tree.resolve()
    target = (tree / rel).resolve()
    if root not in target.parents:
        raise _err(rel, "resolves outside the deployment checkout")
    if not target.is_file():
        raise _err(rel, "no such ciphertext file in the checkout")
    return target


def _decrypt(src: Path, rel: str, key: Path) -> bytes:
    sops = shutil.which("sops")
    if sops is None:
        raise _err(rel, "sops is not installed on this host")
    if not key.is_file():
        raise _err(rel, f"age key {key} is missing")
    proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
        [sops, "--decrypt", "--input-type", "dotenv", "--output-type", "dotenv", str(src)],
        env={**os.environ, "SOPS_AGE_KEY_FILE": str(key)},
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        why = proc.stderr.decode(errors="replace").strip()[:_STDERR_LIMIT]
        raise _err(rel, f"sops could not decrypt with {key.name} (exit {proc.returncode}): {why}")
    return proc.stdout


def _write(target: Path, data: bytes) -> None:
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.chmod(0o700)
    tmp = target.with_name(f".{target.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    tmp.replace(target)


def render(name: str, tenant: str | None, tree: Path, entries: list[EnvFrom]) -> list[Path]:
    """Decrypt every `sopsFile` entry; return the plaintext paths in manifest order.

    Args:
        name: The deployment name (the tmpfs subdirectory).
        tenant: The source's tenant, or None for the platform source.
        tree: The deployment's checkout; `sopsFile` must resolve inside it.
        entries: The manifest's `envFrom` entries; `secretRef` ones are skipped.

    Raises:
        SecretError: On any missing file, key or binary, or a decrypt failure.
    """
    key = paths.AGE_DIR / f"{key_name(tenant)}.key"
    rendered: list[tuple[Path, bytes]] = []
    for e in entries:
        if e.sops_file is None:
            continue
        src = _resolve(tree, e.sops_file)
        stem = src.name.removesuffix(_SUFFIX)
        rendered.append((paths.RUN_SECRETS / name / f"{stem}.env", _decrypt(src, e.sops_file, key)))
    # Write only after every entry decrypted, so a failure leaves no half set behind.
    for target, data in rendered:
        _write(target, data)
    return [t for t, _ in rendered]
