"""Shared pytest config: gate the integration tier behind NUK_INTEGRATION.

The default `uv run pytest` must stay fast and host-independent — no docker, no
/opt/nuklaut. Integration tests (marked `@pytest.mark.integration`) are still
collected, but skipped unless NUK_INTEGRATION=1 is set (CI's integration job
sets it; see .github/workflows/integration.yml).
"""

from __future__ import annotations

import os

import pytest


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
