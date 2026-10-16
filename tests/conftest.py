"""Shared pytest config: gate the integration tier behind NUK_INTEGRATION.

The default `uv run pytest` must stay fast and host-independent — no docker, no
/opt/nuklaut. Integration tests (marked `@pytest.mark.integration`) are still
collected, but skipped unless NUK_INTEGRATION=1 is set (CI's integration job
sets it; see .github/workflows/integration.yml).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import nuk
import pytest

if TYPE_CHECKING:
    from pathlib import Path


def pytest_collection_modifyitems(config, items):
    """Skip integration-marked tests unless NUK_INTEGRATION is set."""
    if os.environ.get("NUK_INTEGRATION"):
        return
    skip = pytest.mark.skip(
        reason="integration tier — set NUK_INTEGRATION=1 (needs docker postgres+redis)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


def stub_apply(
    tmp_path: Path,
    monkeypatch,
    lines: list[tuple[str, ...]],
    *,
    real_override: bool = False,
) -> None:
    """Stub everything `cmd_apply` touches outside the tree; record `sh` calls.

    Shared by the strategy and migrate test modules: both drive `cmd_apply` end to
    end and need the same perimeter (tree paths, the privilege check, the apply
    loop's side effects) stubbed so only the rollout logic is under test.
    """
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    if not real_override:
        monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["compose", "-p", "kolbe"])
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: lines.append(cmd))
