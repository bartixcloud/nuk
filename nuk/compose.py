#!/usr/bin/env python3
"""Compose support: args, override writing, digest resolution."""

from __future__ import annotations

import json
import subprocess  # noqa: S404
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING

import yaml

import nuk

if TYPE_CHECKING:
    from nuk import ComposeImage
    from nuk.models import Ingress, Spec


def compose_args(name: str, spec: Spec) -> list[str]:
    """Build the `docker compose` base argv for an app from its spec."""
    repo = nuk._repo_dir(name)
    override = nuk.project_dir(name) / "compose.override.yml"
    args = ["docker", "compose", "-p", name, "-f", str(repo / spec.compose.file)]
    if override.exists():
        args += ["-f", str(override)]
    for ref in resolve_env_from(spec):
        args += ["--env-file", ref]
    return args


def resolve_env_from(spec: Spec) -> list[str]:
    """Resolve `spec.envFrom[].secretRef` entries to existing file paths.

    Uses the same resolution `compose_args` applies for `--env-file`; only
    existing paths are kept.

    Args:
        spec: The typed manifest `spec`.

    Returns:
        The existing secret-file paths, in manifest order.
    """
    return [e.secret_ref for e in spec.env_from if e.secret_ref and Path(e.secret_ref).exists()]


def _published_port(ing: Ingress) -> int:
    """The host port a non-entry host publishes an ingress on: `hostPort`, else `port`.

    The publish (build_override) and the edge's backend (backend_address) must agree.
    """
    port = ing.host_port or ing.port
    assert port is not None  # noqa: S101  # narrows int|None for ty; a publish always has a port
    return port


def write_override(  # noqa: PLR0913, PLR0917  # thin writer over build_override's frozen API
    name: str,
    ingress: list[Ingress],
    db_env: str | None = None,
    env_from: list[str] | None = None,
    db_services: list[str] | None = None,
    publish_ip: str | None = None,
    local_data: bool = True,
    *,
    colours: list[str] | None = None,
    public_url: str | None = None,
) -> None:
    """Render and write `compose.override.yml` for an app (no-op when empty)."""
    doc = nuk.build_override(
        name,
        ingress,
        db_env,
        env_from,
        db_services,
        publish_ip,
        local_data,
        colours=colours,
        public_url=public_url,
    )
    if doc is None:
        return
    (nuk.project_dir(name) / "compose.override.yml").write_text(yaml.safe_dump(doc.to_wire()))


def compose_service_names(name: str, spec: Spec) -> list[str]:
    """Return the service names declared in an app's checked-out compose file.

    Used by `attachAll` to enumerate every service that should receive the DB
    creds. Returns an empty list when the compose file is absent or has no
    services (the caller then injects nowhere rather than failing the apply).

    Args:
        name: The deployment name (locates `<project_dir>/repo`).
        spec: The typed manifest `spec` (for `compose.file`).

    Returns:
        The compose `services` keys, in file order.
    """
    path = nuk._repo_dir(name) / spec.compose.file
    if not path.exists():
        return []
    # The compose file is the app's own, not validated here: only `services` is read.
    doc: object = yaml.safe_load(path.read_text()) or {}
    services = doc.get("services") if isinstance(doc, dict) else None
    return list(services.keys()) if isinstance(services, dict) else []


def resolve_db_services(name: str, spec: Spec, db_env: str | None) -> list[str]:
    """Resolve which compose services the provisioned DB creds attach to.

    Precedence: `attachAll` (every compose service) > `attachTo` (explicit list)
    > the ingress services (legacy default). Empty when no database was
    provisioned.

    Args:
        name: The deployment name.
        spec: The typed manifest `spec`.
        db_env: The provisioned creds path, or None when no DB was requested.

    Returns:
        The service names to inject DATABASE_URL / REDIS_URL into.
    """
    if not db_env:
        return []
    if spec.databases.attach_all:
        return compose_service_names(name, spec)
    if spec.databases.attach_to:
        return list(spec.databases.attach_to)
    return [i.service for i in spec.ingress if i.service]


def _parse_compose_images_json(text: str) -> list[ComposeImage]:
    """Parse `docker compose images --format json` output (one array or JSON-lines)."""
    text = text.strip()
    if not text:
        return []
    try:
        if text.startswith("["):
            data = json.loads(text)
            rows = data if isinstance(data, list) else []
        else:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (ValueError, json.JSONDecodeError):
        return []
    return [nuk.ComposeImage.from_wire(row) for row in rows if isinstance(row, dict)]


def _primary_container(name: str, spec: Spec) -> str | None:
    """Container name of the deployment's primary service, or None if it names none.

    The probe service of a blue-green strategy (in the active colour), else the
    first ingress backend: the service whose image IS the release.
    """
    if spec.strategy is not None and spec.strategy.type == "blue-green":
        return nuk._container_name(name, spec.strategy.health.service, nuk.active_colour(name))
    service = spec.ingress[0].service if spec.ingress else None
    return nuk._container_name(name, service) if service else None


def _resolve_image_digest(name: str, spec: Spec) -> str | None:
    """Best-effort digest of the app's primary compose image, or None if unresolvable.

    `compose images` lists rows in no stable order, so the row is the primary
    service's (`_primary_container`), else the first by container name. A tagged
    image is looked up by `repo:tag`; a digest-pinned one (Compose reports Tag
    "") has no tag to look up, so it is resolved by its image ID.
    """
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, spec), "images", "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    rows = _parse_compose_images_json(proc.stdout)
    if not rows or not rows[0].repository:
        return None
    primary = _primary_container(name, spec)
    image = next(
        (r for r in rows if primary and r.container_name == primary),
        min(rows, key=lambda r: r.container_name or ""),
    )
    if not image.repository:
        return None
    reference = f"{image.repository}:{image.tag}" if image.tag else image.image_id
    if not reference:
        return None
    try:
        digest = subprocess.run(  # noqa: S603  # fixed argv, no shell
            ["docker", "inspect", "--format", "{{index .RepoDigests 0}}", reference],  # noqa: S607  # docker on PATH
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None
    return digest or None


def _compose_images(name: str, spec: Spec) -> list[str]:
    """The image references the compose project resolves to, in service order."""
    try:
        proc = subprocess.run(  # noqa: S603  # fixed argv, no shell
            [*compose_args(name, spec), "config", "--images"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
