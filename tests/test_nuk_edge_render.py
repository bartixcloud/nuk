"""The edge renders every router from git (spec §6).

Backends resolve from the org manifest, never from anything an app host authored.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest
import yaml

if TYPE_CHECKING:
    from pathlib import Path

import nuk

ORG = """
    apiVersion: nukorg/v1
    kind: Org
    metadata: {name: astrojones}
    domains: [example.com]
    platformDomain: example.com
    acmeEmail: admin@example.com
    network:
      cidr: 10.0.0.0/16
      cloudSubnet: 10.0.1.0/24
      vswitchSubnet: 10.0.10.0/24
      vswitchVlan: 4001
    hosts:
      - {name: metal,   provider: manual, role: hypervisor, privateIp: 10.0.2.2}
      - {name: ingress, provider: incus, role: edge, privateIp: 10.0.10.241, metal: metal}
      - {name: deploy,  provider: incus, role: app,  privateIp: 10.0.10.107, metal: metal}
      - {name: db,      provider: incus, role: data, privateIp: 10.0.10.180, metal: metal}
    facilities:
      dns: wildcard
      tls: dns01
      dnsProvider: hetzner
      secrets: sops
      runners: persistent
    mesh: tailscale
"""

HELLO = """
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: hello}
    spec:
      placement: {role: app}
      source: {repo: https://github.com/astrojones/hello.git}
      ingress:
        - {host: hello.example.com, service: web, port: 8080}
"""

GATE_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: basic-auth}
    spec:
      placement: {role: edge}
      provides:
        route: {capability: basic, middlewares: [auth@file]}
"""


def _tree(tmp_path: Path, deployments: dict[str, str], facilities: dict[str, str]) -> Path:
    for sub, docs in (("deployments", deployments), ("facilities", facilities)):
        d = tmp_path / sub
        d.mkdir(parents=True, exist_ok=True)
        for name, body in docs.items():
            (d / f"{name}.yml").write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    org = tmp_path / "org.yml"
    org.write_text(textwrap.dedent(ORG).lstrip(), encoding="utf-8")
    return tmp_path


def test_backend_resolves_from_the_org_manifest(tmp_path):
    """Spec §6: backend private IP comes from the org manifest, per placement."""
    tree = _tree(tmp_path, {"hello": HELLO}, {"basic": GATE_FACILITY})
    org = nuk.load_org(tree / "org.yml")
    hello = nuk.load_deployments(tree)[0]
    assert nuk.backend_address(org, hello, hello.raw["spec"]["ingress"][0]) == "10.0.10.107:8080"


def test_backend_honours_an_explicit_address(tmp_path):
    """An entry that already names a remote backend passes through untouched."""
    tree = _tree(tmp_path, {"hello": HELLO}, {})
    org = nuk.load_org(tree / "org.yml")
    hello = nuk.load_deployments(tree)[0]
    ing = {"host": "x.example.com", "address": "192.0.2.9:9000"}
    assert nuk.backend_address(org, hello, ing) == "192.0.2.9:9000"


def test_backend_honours_host_port(tmp_path):
    tree = _tree(tmp_path, {"hello": HELLO}, {})
    org = nuk.load_org(tree / "org.yml")
    hello = nuk.load_deployments(tree)[0]
    ing = {"host": "x.example.com", "service": "web", "port": 8080, "hostPort": 18080}
    assert nuk.backend_address(org, hello, ing) == "10.0.10.107:18080"


def test_backend_refuses_an_unplaced_deployment(tmp_path):
    """Without placement the edge cannot know which host to point at. Refuse."""
    unplaced = HELLO.replace("      placement: {role: app}\n", "")
    tree = _tree(tmp_path, {"hello": unplaced}, {})
    org = nuk.load_org(tree / "org.yml")
    hello = nuk.load_deployments(tree)[0]
    with pytest.raises(ValueError, match=r"no spec\.placement"):
        nuk.backend_address(org, hello, hello.raw["spec"]["ingress"][0])


def test_backend_refuses_a_role_the_org_does_not_declare(tmp_path):
    """Placement naming a role with no host is a manifest the org cannot serve."""
    orphan = HELLO.replace("role: app", "role: all-in-one")
    tree = _tree(tmp_path, {"hello": orphan}, {})
    org = nuk.load_org(tree / "org.yml")
    hello = nuk.load_deployments(tree)[0]
    with pytest.raises(ValueError, match="no host with role"):
        nuk.backend_address(org, hello, hello.raw["spec"]["ingress"][0])


def test_edge_renders_a_router_for_every_deployment(tmp_path, monkeypatch):
    tree = _tree(
        tmp_path,
        {"hello": HELLO, "other": HELLO.replace("hello", "other")},
        {"basic": GATE_FACILITY},
    )
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    rendered = nuk.render_edge_routers(tree, nuk.load_org(tree / "org.yml"))
    assert sorted(rendered) == ["hello", "other"]
    doc = yaml.safe_load((dynamic / "hello.yml").read_text())
    assert doc["http"]["services"]["hello-0"]["loadBalancer"]["servers"] == [
        {"url": "http://10.0.10.107:8080"}
    ]


def test_edge_render_applies_the_gate_from_the_vocabulary(tmp_path, monkeypatch):
    gated = HELLO.replace("port: 8080}", "port: 8080, auth: basic}")
    tree = _tree(tmp_path, {"hello": gated}, {"basic": GATE_FACILITY})
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    nuk.render_edge_routers(tree, nuk.load_org(tree / "org.yml"))
    doc = yaml.safe_load((dynamic / "hello.yml").read_text())
    assert doc["http"]["routers"]["hello-0"]["middlewares"] == [
        "auth@file",
        "maintenance-errors@file",
    ]


def test_edge_render_skips_deployments_without_ingress(tmp_path, monkeypatch):
    headless = HELLO.split("      ingress:")[0]
    tree = _tree(tmp_path, {"hello": headless}, {})
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    assert nuk.render_edge_routers(tree, nuk.load_org(tree / "org.yml")) == []
    assert not (dynamic / "hello.yml").exists()


@pytest.mark.parametrize("role", ["edge", "all-in-one"])
def test_edge_render_skips_deployments_placed_on_an_entry_host(tmp_path, monkeypatch, role):
    """A deployment placed on the edge (or all-in-one) renders its OWN router.

    cmd_apply writes it locally with a container-name backend, because it is
    co-located with Traefik. Re-rendering it here would clobber that working
    file with a `privateIp:port` nothing is listening on.
    """
    local = HELLO.replace("role: app", f"role: {role}")
    tree = _tree(tmp_path, {"hello": local}, {"basic": GATE_FACILITY})
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    (dynamic / "hello.yml").write_text("http: {local: true}\n", encoding="utf-8")
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    assert nuk.render_edge_routers(tree, nuk.load_org(tree / "org.yml")) == []
    assert yaml.safe_load((dynamic / "hello.yml").read_text()) == {"http": {"local": True}}


def test_reap_removes_only_the_legacy_worker_prefix(tmp_path, monkeypatch):
    """Spec §11 step 6: the one-time reap, scoped exactly to what delivery wrote."""
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    for name in ("worker-hello.yml", "worker-other.yml", "global.yml", "hello.yml", "oauth.yml"):
        (dynamic / name).write_text("http: {}\n", encoding="utf-8")
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    reaped = nuk.reap_legacy_worker_routers()
    assert sorted(reaped) == ["worker-hello.yml", "worker-other.yml"]
    assert sorted(p.name for p in dynamic.iterdir()) == ["global.yml", "hello.yml", "oauth.yml"]


def test_reap_is_idempotent(tmp_path, monkeypatch):
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    assert nuk.reap_legacy_worker_routers() == []
    assert nuk.reap_legacy_worker_routers() == []


def test_render_edge_routers_reaps_first(tmp_path, monkeypatch):
    """A stale worker-hello.yml and a fresh hello.yml define the SAME router key.

    Traefik resolves that nondeterministically, so the stale one must be gone
    before the fresh one is published — not merely at some later point.
    """
    tree = _tree(tmp_path, {"hello": HELLO}, {"basic": GATE_FACILITY})
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    (dynamic / "worker-hello.yml").write_text("http: {}\n", encoding="utf-8")
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    nuk.render_edge_routers(tree, nuk.load_org(tree / "org.yml"))
    assert not (dynamic / "worker-hello.yml").exists()
    assert (dynamic / "hello.yml").exists()


def test_edge_dynamic_staging_is_gone():
    """The staging dir and both writers are deleted, not deprecated."""
    for gone in ("EDGE_DYNAMIC", "write_edge_ingress", "rewrite_ingress_for_edge"):
        assert not hasattr(nuk, gone), f"{gone} should have been deleted"


def test_reap_does_not_remove_a_current_worker_named_deployment(tmp_path, monkeypatch):
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    (dynamic / "worker-app.yml").write_text("http: {}\n", encoding="utf-8")
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    assert nuk.reap_legacy_worker_routers(protected={"worker-app.yml"}) == []
    assert (dynamic / "worker-app.yml").exists()
