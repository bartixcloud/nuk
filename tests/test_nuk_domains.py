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
    # With no loans, the authorized tenant IS the zone owner (spec §3.1).
    assert nuk.resolve_host_owner("kolbe.astrojones.guru", REG, {}) == "astrojones"
    assert nuk.resolve_host_owner("other.de", REG, {}) is None


def test_delegation_transfers_and_the_owner_loses_it():
    assert nuk.resolve_host_owner("kolbe.astrojones.guru", REG, DELEG) == "kolbeapp-de"
    assert nuk.resolve_host_owner("x.astrojones.guru", REG, DELEG) == "astrojones"


def test_zone_owner_is_none_when_nobody_owns_the_host():
    assert nuk.resolve_host_owner("nobody.example.com", REG, {}) is None


def test_the_most_specific_loan_wins_regardless_of_file_order():
    """Spec §3.2: a broader loan must not shadow a more specific one (YAML order is ignored)."""
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["example.com", "*.example.com"]},
            {"name": "a", "domains": []},
            {"name": "b", "domains": []},
        ]
    )
    broader_first = {
        "astrojones": [
            nuk.Delegation(host="*.example.com", to="a"),
            nuk.Delegation(host="special.example.com", to="b"),
        ]
    }
    specific_first = {"astrojones": list(reversed(broader_first["astrojones"]))}
    assert nuk.resolve_host_owner("special.example.com", reg, broader_first) == "b"
    assert nuk.resolve_host_owner("special.example.com", reg, specific_first) == "b"
    assert nuk.resolve_host_owner("x.example.com", reg, broader_first) == "a"


def test_foreign_pattern_without_delegation_is_an_error():
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": ["kolbe.astrojones.guru"]},
        ]
    )
    with pytest.raises(SystemExit):
        nuk.check_cross_zone_patterns("kolbeapp-de", reg, {})  # kolbe.* ohne Delegation
    nuk.check_cross_zone_patterns(
        "kolbeapp-de",
        reg,
        {"astrojones": [nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de")]},
    )  # ok


DELEG_YML = """\
apiVersion: nuk/v1
kind: Delegations
metadata: {name: astrojones}
spec:
  delegations:
    - {host: kolbe.astrojones.guru, to: kolbeapp-de}
"""


def test_load_delegations_parses(tmp_path):
    (tmp_path / "delegations.yml").write_text(DELEG_YML, encoding="utf-8")
    dels = nuk.load_delegations(tmp_path)
    assert [(d.host, d.to) for d in dels] == [("kolbe.astrojones.guru", "kolbeapp-de")]


def test_load_delegations_missing_file_is_empty(tmp_path):
    assert nuk.load_delegations(tmp_path) == []


def test_load_delegations_malformed_refuses(tmp_path):
    (tmp_path / "delegations.yml").write_text("kind: Delegations\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        nuk.load_delegations(tmp_path)


def test_validate_delegation_without_coverage_refuses():
    reg = nuk.TenantRegistry(tenants=[{"name": "astrojones", "domains": ["astrojones.guru"]}])
    with pytest.raises(SystemExit):
        nuk.validate_delegations(
            "astrojones", [nuk.Delegation(host="x.other.de", to="jonesh")], reg
        )


def test_validate_delegation_to_unknown_tenant_refuses():
    reg = nuk.TenantRegistry(
        tenants=[{"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]}]
    )
    with pytest.raises(SystemExit):
        nuk.validate_delegations(
            "astrojones", [nuk.Delegation(host="kolbe.astrojones.guru", to="nobody")], reg
        )


def test_validate_delegation_to_a_target_that_lists_the_host_refuses():
    """Ein-Ebenen: das Ziel darf den verliehenen Host nicht selbst listen.

    Täte es das, wäre es selbst Zonen-Eigentümer und könnte weiterverleihen.
    """
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": ["kolbe.astrojones.guru"]},
        ]
    )
    with pytest.raises(SystemExit):
        nuk.validate_delegations(
            "astrojones", [nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de")], reg
        )


def test_validate_delegation_accepts_owner_zones_and_empty_target_domains():
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": []},
        ]
    )
    nuk.validate_delegations(
        "astrojones", [nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de")], reg
    )  # no raise


def test_validate_delegation_of_the_same_host_twice_refuses():
    """Two loans of one host are a specificity tie the resolver must not have to break (spec §2)."""
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "astrojones", "domains": ["astrojones.guru", "*.astrojones.guru"]},
            {"name": "kolbeapp-de", "domains": []},
            {"name": "jonesh", "domains": []},
        ]
    )
    with pytest.raises(SystemExit):
        nuk.validate_delegations(
            "astrojones",
            [
                nuk.Delegation(host="kolbe.astrojones.guru", to="kolbeapp-de"),
                nuk.Delegation(host="kolbe.astrojones.guru", to="jonesh"),
            ],
            reg,
        )


def test_validate_delegation_from_a_broader_than_the_zone_owner_refuses():
    """A tenant that only lists a broader wildcard cannot lend from another's zone (spec §2).

    ``broad`` lists ``*.example.com``; ``owner`` owns the more specific ``special.example.com``.
    A loan of ``special.example.com`` by ``broad`` would be silently ineffective — the resolver
    only consults the real zone owner — so it must be refused at validation time.
    """
    reg = nuk.TenantRegistry(
        tenants=[
            {"name": "broad", "domains": ["*.example.com"]},
            {"name": "owner", "domains": ["special.example.com"]},
            {"name": "target", "domains": []},
        ]
    )
    with pytest.raises(SystemExit):
        nuk.validate_delegations(
            "broad", [nuk.Delegation(host="special.example.com", to="target")], reg
        )
    # The real zone owner may lend it.
    nuk.validate_delegations(
        "owner", [nuk.Delegation(host="special.example.com", to="target")], reg
    )  # no raise


def test_store_and_load_roundtrip(tmp_path):
    nuk.store_delegations(
        tmp_path, "astrojones", [nuk.Delegation(host="k.astrojones.guru", to="kolbeapp-de")]
    )
    cached = nuk.load_cached_delegations(tmp_path, "astrojones")
    assert [(d.host, d.to) for d in cached] == [("k.astrojones.guru", "kolbeapp-de")]


def test_first_run_without_cache_yields_no_delegations(tmp_path):
    assert nuk.load_cached_delegations(tmp_path, "astrojones") == []
