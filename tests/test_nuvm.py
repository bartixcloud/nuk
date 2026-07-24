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


from pathlib import Path


def test_build_create_plan_overlay_then_virtinstall() -> None:
    plan = nuvm.build_create_plan("nuroot-db", vcpu=4, memory_mib=16384, net="br-priv")
    assert plan[0][:4] == ["qemu-img", "create", "-f", "qcow2"]
    assert str(nuvm.overlay_path("nuroot-db")) in plan[0]
    vi = plan[1]
    assert vi[0] == "virt-install"
    assert "--name" in vi and "nuroot-db" in vi
    assert "--memory" in vi and "16384" in vi
    assert "--vcpus" in vi and "4" in vi
    assert "network=br-priv" in " ".join(vi)
    assert "--noautoconsole" in vi and "--import" in vi


def test_build_destroy_plan_is_tolerant_and_removes_state() -> None:
    plan = nuvm.build_destroy_plan("scratch1")
    joined = [" ".join(p) for p in plan]
    assert any("virsh destroy scratch1" in j for j in joined)
    assert any("virsh undefine scratch1" in j for j in joined)
    assert any(str(nuvm.instance_dir("scratch1")) in j for j in joined)


def test_seed_iso_plan_uses_cloud_localds() -> None:
    plan = nuvm.build_seed_iso_plan("nuroot-db")
    assert plan[0][0] == "cloud-localds"
    assert str(nuvm.seed_path("nuroot-db")) in plan[0]


import nuk


def _host(**kw):
    base = {"name": "nuroot-db", "provider": "libvirt", "metal": "nuroot-metal",
            "role": "data", "privateIp": "10.10.2.3", "vcpu": 4, "memory": "16G"}
    base.update(kw)
    return nuk.Host.model_validate(base)


def test_render_substitutes_known_vars_only() -> None:
    out = nuvm._render("host=${HOSTNAME} role=${ROLE} keep=${UNKNOWN} lit=$$X",
                       {"HOSTNAME": "nuroot-db", "ROLE": "data"})
    assert "host=nuroot-db" in out
    assert "role=data" in out
    assert "${UNKNOWN}" in out
    assert "$$X" in out


def test_render_network_config_static_ip_mtu() -> None:
    nc = nuvm.render_network_config(_host(), gateway="10.10.2.1", prefixlen=24)
    assert "10.10.2.3/24" in nc
    assert "10.10.2.1" in nc
    assert "mtu: 1400" in nc
    assert "version: 2" in nc


def test_render_meta_data_has_hostname() -> None:
    md = nuvm.render_meta_data(_host())
    assert "local-hostname: nuroot-db" in md
    assert "instance-id:" in md
