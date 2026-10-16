"""Unit tests for tenant-registry domain ownership (spec §1/§3 domain patterns).

Pure pydantic — no /opt/nuklaut, no docker, no controller.

    uv run pytest tests/test_nuk_domains.py
"""

from __future__ import annotations

import nuk
import pytest
from pydantic import ValidationError


def test_specificity_ranks_by_label_depth():
    assert nuk.specificity("c") == 1
    assert nuk.specificity("*.c") == 1
    assert nuk.specificity("a.b.c") == 3
    assert nuk.specificity("a.b.c") > nuk.specificity("*.b.c") > nuk.specificity("*.c")


def test_registry_allows_overlap_between_tenants():
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": ["kolbe.astrojones.guru"]},
        ]
    )
    assert reg.get("kolbeapp-de").domains == ["kolbe.astrojones.guru"]


def test_registry_rejects_the_same_pattern_twice():
    with pytest.raises(ValidationError):
        nuk.TenantRegistry(
            tenants=[
                {"name": "a", "domains": ["x.de"]},
                {"name": "b", "domains": ["x.de"]},
            ]
        )


def test_registry_rejects_the_same_pattern_case_insensitively():
    with pytest.raises(ValidationError):
        nuk.TenantRegistry(
            tenants=[
                {"name": "a", "domains": ["*.B.C"]},
                {"name": "b", "domains": ["*.b.c"]},
            ]
        )
