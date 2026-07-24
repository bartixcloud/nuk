"""nuvm — turn a nuk libvirt Host into a running VM on its hypervisor.

Pure command-planners (build_*_plan) + seed rendering + a typer CLI. The
planners return lists of argv so they are unit-testable without libvirt; the
CLI executes them, or prints them under --dry-run.

    uv run pytest tests/test_nuvm.py
"""

from __future__ import annotations

import re

_MEM_RE = re.compile(r"^\s*(\d+)\s*([GMgm]?)\s*$")


def memory_to_mib(spec: str) -> int:
    """Parse a memory spec like '16G' or '512M' (bare = MiB) into MiB."""
    m = _MEM_RE.match(spec)
    if not m:
        msg = f"invalid memory spec: {spec!r}"
        raise ValueError(msg)
    value, unit = int(m.group(1)), m.group(2).upper()
    return value * 1024 if unit == "G" else value
