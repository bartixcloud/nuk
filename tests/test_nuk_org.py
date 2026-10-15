"""Unit tests for the nukorg/v1 org capability manifest + `nuk org` helpers.

Pure pyyaml/pydantic — no /opt/nuklaut, no docker, no controller.

    uv run pytest tests/test_nuk_org.py
"""

from __future__ import annotations

import nuk
import pytest
import yaml

# A valid multi-host org: one edge entry-point, a bare-metal hypervisor, and a
# libvirt VM on it. Exercises every topology invariant at once.
ORG_DOC = {
    "apiVersion": "nukorg/v1",
    "kind": "Org",
    "metadata": {"name": "astrojones"},
    "domains": ["astrojones.guru", "bitcoinalchemist.com"],
    "platformDomain": "astrojones.guru",
    "acmeEmail": "admin@astrojones.guru",
    "network": {
        "cidr": "10.10.0.0/16",
        "cloudSubnet": "10.10.1.0/24",
        "vswitchSubnet": "10.10.2.0/24",
        "vswitchVlan": 4001,
    },
    "hosts": [
        {
            "name": "hcbase",
            "provider": "hcloud",
            "type": "cx23",
            "role": "edge",
            "privateIp": "10.10.1.2",
        },
        {
            "name": "nuroot-metal",
            "provider": "manual",
            "ip": "1.2.3.4",
            "role": "hypervisor",
            "privateIp": "10.10.2.2",
        },
        {
            "name": "nuroot-db",
            "provider": "libvirt",
            "metal": "nuroot-metal",
            "role": "data",
            "privateIp": "10.10.2.3",
        },
    ],
    "facilities": {
        "dns": "wildcard",
        "tls": "dns01",
        "dnsProvider": "hetzner",
        "secrets": "sops",
        "runners": "ephemeral",
    },
    "mesh": "tailscale",
    "overlays": ["host-tooling-claude"],
}

# The single-host all-in-one shape (Kapitel 1): no private network, mesh may be none.
ONE_HOST_DOC = {
    "apiVersion": "nukorg/v1",
    "kind": "Org",
    "metadata": {"name": "astrojones"},
    "domains": ["astrojones.guru", "bitcoinalchemist.com"],
    "platformDomain": "astrojones.guru",
    "acmeEmail": "admin@astrojones.guru",
    "hosts": [
        {
            "name": "hcbase",
            "provider": "hcloud",
            "type": "cx23",
            "role": "all-in-one",
            "privateIp": "10.10.1.2",
        },
    ],
    "facilities": {
        "dns": "wildcard",
        "tls": "dns01",
        "dnsProvider": "hetzner",
        "secrets": "sops",
        "runners": "ephemeral",
    },
    "mesh": "none",
}


def _facilities(**over: object) -> dict:
    """ORG_DOC with a shallow override of the facilities block."""
    return {**ORG_DOC, "facilities": {**ORG_DOC["facilities"], **over}}


def _hosts(hosts: list[dict], **over: object) -> dict:
    """ORG_DOC with a replaced hosts[] (and optional top-level overrides)."""
    return {**ORG_DOC, "hosts": hosts, **over}


# --- schema ------------------------------------------------------------------


def test_org_parses_full_manifest():
    org = nuk.Org.model_validate(ORG_DOC)
    assert org.metadata.name == "astrojones"
    assert org.domains == ["astrojones.guru", "bitcoinalchemist.com"]
    assert org.platform_domain == "astrojones.guru"
    assert org.acme_email == "admin@astrojones.guru"
    assert org.network.vswitch_vlan == 4001
    assert [h.name for h in org.hosts] == ["hcbase", "nuroot-metal", "nuroot-db"]
    assert "auth" not in nuk.Facilities.model_fields  # the gate belongs to the route, not the org
    assert org.mesh == "tailscale"


def test_org_one_host_all_in_one_no_network():
    org = nuk.Org.model_validate(ONE_HOST_DOC)
    assert org.network is None
    assert org.mesh == "none"
    assert org.hosts[0].role == "all-in-one"


def test_org_rejects_unknown_enum():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(runners="swarm"))


def test_org_rejects_bad_provider():
    bad = [{**ORG_DOC["hosts"][0], "provider": "pulumi"}]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(bad, mesh="none"))


# --- facilities coupling -----------------------------------------------------


def test_org_wildcard_requires_dns01():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(dns="wildcard", tls="http01"))


def test_org_dns01_requires_provider():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(dns="wildcard", tls="dns01", dnsProvider=None))


def test_org_manual_requires_http01():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(dns="manual", tls="dns01", dnsProvider="hetzner"))


def test_org_manual_http01_ok():
    org = nuk.Org.model_validate(_facilities(dns="manual", tls="http01", dnsProvider=None))
    assert org.facilities.dns == "manual"


# --- topology invariants -----------------------------------------------------


def test_org_platform_domain_must_be_in_domains():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate({**ORG_DOC, "platformDomain": "not-managed.example"})


def test_org_requires_exactly_one_entry_point():
    two_edges = [
        {"name": "a", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {"name": "b", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.3"},
    ]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(two_edges))


def test_org_rejects_zero_entry_points():
    no_edge = [{"name": "w", "provider": "hcloud", "role": "app", "privateIp": "10.10.1.2"}]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(no_edge, mesh="none"))


def test_org_mesh_none_only_single_host():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate({**ORG_DOC, "mesh": "none"})


def test_org_libvirt_requires_metal():
    hosts = [
        {"name": "hcbase", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {"name": "vm", "provider": "libvirt", "role": "app", "privateIp": "10.10.2.3"},
    ]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(hosts))


def test_org_libvirt_metal_must_be_hypervisor():
    hosts = [
        {"name": "hcbase", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {
            "name": "vm",
            "provider": "libvirt",
            "metal": "hcbase",
            "role": "app",
            "privateIp": "10.10.2.3",
        },
    ]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(hosts))


def test_org_accepts_incus_provider():
    hosts = [
        {"name": "metal", "provider": "manual", "role": "hypervisor", "privateIp": "10.0.2.2"},
        {
            "name": "ingress",
            "provider": "incus",
            "metal": "metal",
            "role": "edge",
            "privateIp": "10.0.10.241",
        },
        {
            "name": "deploy",
            "provider": "incus",
            "metal": "metal",
            "role": "app",
            "privateIp": "10.0.10.107",
        },
        {
            "name": "nuroot-db",
            "provider": "incus",
            "metal": "metal",
            "role": "data",
            "privateIp": "10.0.10.180",
        },
    ]
    doc = {
        **ORG_DOC,
        "hosts": hosts,
        "mesh": "none",
        "network": {**ORG_DOC["network"], "vswitchSubnet": "10.0.10.0/24"},
    }
    org = nuk.Org.model_validate(doc)
    assert org.mesh == "none"
    assert len(org.hosts) == 4


def test_org_incus_requires_metal():
    hosts = [
        {"name": "ingress", "provider": "incus", "role": "edge", "privateIp": "10.0.10.241"},
    ]
    with pytest.raises(ValueError, match="incus requires 'metal'"):
        nuk.Org.model_validate({**ORG_DOC, "hosts": hosts, "mesh": "none"})


def test_org_hypervisor_exempt_from_subnets():
    # metal's privateIp (10.0.2.2) is NOT in vswitchSubnet — hypervisor hosts are exempt.
    hosts = [
        {"name": "metal", "provider": "manual", "role": "hypervisor", "privateIp": "10.0.2.2"},
        {
            "name": "ingress",
            "provider": "incus",
            "metal": "metal",
            "role": "edge",
            "privateIp": "10.0.10.241",
        },
    ]
    doc = {
        **ORG_DOC,
        "hosts": hosts,
        "mesh": "none",
        "network": {**ORG_DOC["network"], "vswitchSubnet": "10.0.10.0/24"},
    }
    nuk.Org.model_validate(doc)  # must NOT raise


def test_org_private_ip_must_be_unique():
    dup = [
        {"name": "a", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {"name": "b", "provider": "hcloud", "role": "app", "privateIp": "10.10.1.2"},
    ]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(dup))


def test_org_private_ip_must_match_subnet():
    # hcloud host addressed out of the cloudSubnet (into the vswitchSubnet) → reject.
    wrong = [
        {"name": "hcbase", "provider": "hcloud", "role": "edge", "privateIp": "10.10.2.9"},
        {
            "name": "nuroot-metal",
            "provider": "manual",
            "role": "hypervisor",
            "privateIp": "10.10.2.2",
        },
    ]
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_hosts(wrong))


# --- ingress-host coverage ---------------------------------------------------


def _manifest(host: str) -> nuk.Deployment:
    return nuk.Deployment.model_validate(
        {
            "apiVersion": "nuk/v1",
            "kind": "Deployment",
            "metadata": {"name": "app"},
            "spec": {"ingress": [{"host": host, "service": "web", "port": 80}]},
        }
    )


def test_validate_ingress_hosts_accepts_managed_domain():
    org = nuk.Org.model_validate(ORG_DOC)
    nuk.validate_ingress_hosts(org, _manifest("cognee.bitcoinalchemist.com"))  # no raise


def test_validate_ingress_hosts_rejects_foreign_domain():
    org = nuk.Org.model_validate(ORG_DOC)
    with pytest.raises(SystemExit):
        nuk.validate_ingress_hosts(org, _manifest("cognee.example.org"))


# --- loader / accessor -------------------------------------------------------


def test_load_org_roundtrip(tmp_path):
    p = tmp_path / "nuklaut.org.yml"
    p.write_text(yaml.safe_dump(ORG_DOC), encoding="utf-8")
    assert nuk.load_org(p).metadata.name == "astrojones"


def test_astrocloud_libvirt_data_host_validates(tmp_path) -> None:
    doc = dict(ORG_DOC)  # ORG_DOC already carries nuroot-metal + nuroot-db
    p = tmp_path / "org.yml"
    p.write_text(yaml.safe_dump(doc))
    org = nuk.load_org(p)
    db = next(h for h in org.hosts if h.name == "nuroot-db")
    assert db.provider == "libvirt"
    assert db.metal == "nuroot-metal"
    assert db.private_ip.startswith("10.10.2.")


def test_load_org_invalid_exits(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("apiVersion: nukorg/v1\nkind: Org\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        nuk.load_org(p)


def test_org_get_dotted_by_alias():
    org = nuk.Org.model_validate(ORG_DOC)
    assert nuk.org_get(org, "facilities.dnsProvider") == "hetzner"
    assert nuk.org_get(org, "platformDomain") == "astrojones.guru"
    assert nuk.org_get(org, "metadata.name") == "astrojones"


def test_org_get_missing_key_exits():
    org = nuk.Org.model_validate(ORG_DOC)
    with pytest.raises(SystemExit):
        nuk.org_get(org, "facilities.nope")


# --- org resolution from git remote ------------------------------------------


def test_origin_org_from_github_url(monkeypatch):
    monkeypatch.setattr(nuk, "git_origin", lambda _p: "https://github.com/ekd-akd/oauth")
    assert nuk.origin_org() == "ekd-akd"


def test_origin_org_none_without_remote(monkeypatch):
    monkeypatch.setattr(nuk, "git_origin", lambda _p: None)
    assert nuk.origin_org() is None


def test_org_rejects_retired_worker_role():
    """`worker` was renamed to `app` (spec §3.1); the alias is retired so a stale
    manifest fails loudly instead of validating into a role nothing else knows.
    """
    with pytest.raises(nuk.ValidationError):
        nuk.Host(name="w", provider="incus", role="worker", privateIp="10.0.10.107")


def test_org_accepts_app_role():
    """`app` is the rename of `worker` (spec §3.1). Both are accepted during the
    migration so the nuk and infra submodules can be bumped independently.
    """
    hosts = [
        {"name": "ingress", "provider": "incus", "role": "edge", "privateIp": "10.0.10.241"},
        {"name": "deploy", "provider": "incus", "role": "app", "privateIp": "10.0.10.107"},
    ]
    assert [h.role for h in [nuk.Host(**h) for h in hosts]] == ["edge", "app"]


# --- singleton roles (spec §3.1) -------------------------------------------------


def test_org_allows_two_app_hosts():
    """Spec §13: a second app host (the dedicated Kolbe VM) is legal."""
    hosts = [
        {"name": "edge", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {
            "name": "m",
            "provider": "manual",
            "ip": "1.2.3.4",
            "role": "hypervisor",
            "privateIp": "10.10.2.2",
        },
        {
            "name": "deploy",
            "provider": "incus",
            "metal": "m",
            "role": "app",
            "privateIp": "10.10.1.3",
        },
        {
            "name": "kolbe-app",
            "provider": "incus",
            "metal": "m",
            "role": "app",
            "privateIp": "10.10.1.4",
        },
    ]
    # incus hosts are VMs: they must sit in the vswitchSubnet (mirrors
    # test_org_accepts_incus_provider), so widen it to cover their IPs.
    doc = _hosts(hosts, network={**ORG_DOC["network"], "vswitchSubnet": "10.10.1.0/24"})
    org = nuk.Org.model_validate(doc)
    assert [h.name for h in org.hosts if h.role == "app"] == ["deploy", "kolbe-app"]


def test_org_rejects_two_data_hosts():
    hosts = [
        {"name": "edge", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {"name": "a", "provider": "hcloud", "role": "data", "privateIp": "10.10.1.3"},
        {"name": "b", "provider": "hcloud", "role": "data", "privateIp": "10.10.1.4"},
    ]
    with pytest.raises(nuk.ValidationError, match="at most one host may have role 'data'"):
        nuk.Org.model_validate(_hosts(hosts))


def test_org_allows_two_hypervisors():
    """The broker spawns ephemeral VMs per metal box; placement never targets the role."""
    hosts = [
        {"name": "edge", "provider": "hcloud", "role": "edge", "privateIp": "10.10.1.2"},
        {
            "name": "m1",
            "provider": "manual",
            "ip": "1.2.3.4",
            "role": "hypervisor",
            "privateIp": "10.10.2.2",
        },
        {
            "name": "m2",
            "provider": "manual",
            "ip": "1.2.3.5",
            "role": "hypervisor",
            "privateIp": "10.10.2.3",
        },
    ]
    org = nuk.Org.model_validate(_hosts(hosts))
    assert [h.name for h in org.hosts] == ["edge", "m1", "m2"]
