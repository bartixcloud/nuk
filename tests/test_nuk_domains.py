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


REG = nuk.TenantRegistry(
    tenants=[
        {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
        {"name": "kolbeapp-de", "domains": []},
    ]
)
DELEG = {"astrojones": [nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de")]}


def test_zone_owner_is_the_most_specific_pattern():
    assert nuk.zone_owner("kolbe.astrojones.guru", REG) == "astrojones"
    assert nuk.zone_owner("other.de", REG) is None


def test_delegation_transfers_and_the_owner_loses_it():
    assert nuk.resolve_host_owner("kolbe.astrojones.guru", REG, DELEG) == "kolbeapp-de"
    assert nuk.resolve_host_owner("x.astrojones.guru", REG, DELEG) == "astrojones"


def test_zone_owner_is_none_when_nobody_owns_the_host():
    assert nuk.zone_owner("nobody.example.com", REG) is None


def test_foreign_pattern_without_delegation_is_an_error():
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": ["kolbe.astrojones.guru"]},
        ]
    )
    with pytest.raises(SystemExit):
        nuk.check_cross_zone_patterns(reg, {})  # kolbe.* ohne Delegation = Fehler
    nuk.check_cross_zone_patterns(
        reg, {"astrojones": [nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de")]}
    )  # ok
