from __future__ import annotations

import pytest

import nuvm


@pytest.mark.parametrize(
    ("spec", "mib"),
    [("16G", 16384), ("8G", 8192), ("512M", 512), ("1024", 1024)],
)
def test_memory_to_mib(spec: str, mib: int) -> None:
    assert nuvm.memory_to_mib(spec) == mib


def test_memory_to_mib_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="memory"):
        nuvm.memory_to_mib("banana")
