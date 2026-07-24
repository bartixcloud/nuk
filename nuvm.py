"""nuvm — turn a nuk libvirt Host into a running VM on its hypervisor.

Pure command-planners (build_*_plan) + seed rendering + a typer CLI. The
planners return lists of argv so they are unit-testable without libvirt; the
CLI executes them, or prints them under --dry-run.

    uv run pytest tests/test_nuvm.py
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Annotated

import typer

import nuk

_MEM_RE = re.compile(r"^\s*(\d+)\s*([GMgm]?)\s*$")

BASE_IMAGE = Path("/var/lib/nuvm/base/base.qcow2")
INSTANCES = Path("/var/lib/nuvm/instances")


def memory_to_mib(spec: str) -> int:
    """Parse a memory spec like '16G' or '512M' (bare = MiB) into MiB."""
    m = _MEM_RE.match(spec)
    if not m:
        msg = f"invalid memory spec: {spec!r}"
        raise ValueError(msg)
    value, unit = int(m.group(1)), m.group(2).upper()
    return value * 1024 if unit == "G" else value


def instance_dir(name: str) -> Path:
    return INSTANCES / name


def overlay_path(name: str) -> Path:
    return instance_dir(name) / "overlay.qcow2"


def seed_path(name: str) -> Path:
    return instance_dir(name) / "seed.iso"


def build_create_plan(
    name: str, vcpu: int, memory_mib: int, net: str, *, base: Path = BASE_IMAGE
) -> list[list[str]]:
    """qemu-img COW overlay on the base image, then virt-install --import."""
    overlay = overlay_path(name)
    return [
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)],
        [
            "virt-install",
            "--name", name,
            "--vcpus", str(vcpu),
            "--memory", str(memory_mib),
            "--disk", f"path={overlay},format=qcow2",
            "--disk", f"path={seed_path(name)},device=cdrom",
            "--network", f"network={net},model=virtio",
            "--os-variant", "debian13",
            "--graphics", "none",
            "--import",
            "--noautoconsole",
        ],
    ]


def build_seed_iso_plan(name: str) -> list[list[str]]:
    """Pack the rendered NoCloud seed dir into a cloud-init ISO."""
    d = instance_dir(name)
    return [
        [
            "cloud-localds",
            "--network-config", str(d / "network-config"),
            str(seed_path(name)),
            str(d / "user-data"),
            str(d / "meta-data"),
        ]
    ]


def build_destroy_plan(name: str) -> list[list[str]]:
    """Destroy + undefine (tolerant if absent) and delete instance state."""
    return [
        ["virsh", "destroy", name],
        ["virsh", "undefine", name, "--nvram"],
        ["rm", "-rf", str(instance_dir(name))],
    ]


def _render(template: str, variables: dict[str, str]) -> str:
    """Replace ${KEY} for each key in `variables`; leave everything else as-is."""
    out = template
    for key, value in variables.items():
        out = out.replace("${" + key + "}", value)
    return out


def render_network_config(host: nuk.Host, gateway: str, prefixlen: int) -> str:
    """cloud-init NoCloud v2 network config: one virtio NIC, static IP, MTU 1400."""
    return (
        "version: 2\n"
        "ethernets:\n"
        "  primary:\n"
        '    match: {name: "en*"}\n'
        "    mtu: 1400\n"
        f"    addresses: [{host.private_ip}/{prefixlen}]\n"
        "    routes:\n"
        f"      - {{to: default, via: {gateway}}}\n"
    )


def render_meta_data(host: nuk.Host) -> str:
    return f"instance-id: {host.name}-0\nlocal-hostname: {host.name}\n"


NET_PRIV = "br-priv"
NET_CI = "nat-ci"


def resolve_host(org: nuk.Org, name: str) -> nuk.Host:
    for h in org.hosts:
        if h.name == name:
            if h.provider != "libvirt":
                msg = f"host {name!r} is provider {h.provider!r}, not libvirt"
                raise ValueError(msg)
            return h
    msg = f"host {name!r} not found in org"
    raise ValueError(msg)


def net_for(host: nuk.Host, *, ephemeral: bool) -> str:  # noqa: ARG001
    return NET_CI if ephemeral else NET_PRIV


app = typer.Typer(no_args_is_help=True, help="libvirt VM lifecycle for nuk hosts")


def run_plan(plan: list[list[str]], *, dry_run: bool, tolerant: bool = False) -> None:
    for argv in plan:
        if dry_run:
            typer.echo(" ".join(argv))
            continue
        try:
            subprocess.run(argv, check=True)  # noqa: S603
        except subprocess.CalledProcessError:
            if not tolerant:
                raise


def _write_seed(host: nuk.Host, org: nuk.Org) -> None:
    d = instance_dir(host.name)
    d.mkdir(parents=True, exist_ok=True)
    gateway = org.network.vswitch_subnet.rsplit(".", 1)[0] + ".1"
    prefixlen = int(org.network.vswitch_subnet.split("/")[1])
    (d / "network-config").write_text(render_network_config(host, gateway, prefixlen))
    (d / "meta-data").write_text(render_meta_data(host))
    (d / "user-data").write_text("#cloud-config\n")  # P1: minimal; Ops O3 supplies the real template


@app.command()
def up(
    name: str,
    org_file: Annotated[Path, typer.Option("--org-file")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Provision a declared libvirt host from the org manifest (idempotent)."""
    org = nuk.load_org(org_file)
    host = resolve_host(org, name)
    if not dry_run:
        _write_seed(host, org)
    net = net_for(host, ephemeral=False)
    run_plan(build_seed_iso_plan(name), dry_run=dry_run)
    run_plan(
        build_create_plan(name, host.vcpu or 2, memory_to_mib(host.memory or "2G"), net),
        dry_run=dry_run,
    )


@app.command()
def create(
    name: str,
    cpu: Annotated[int, typer.Option("--cpu")] = 2,
    mem: Annotated[str, typer.Option("--mem")] = "2G",
    ephemeral: Annotated[bool, typer.Option("--ephemeral")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create a throwaway VM (ephemeral → nat-ci, else br-priv)."""
    net = NET_CI if ephemeral else NET_PRIV
    run_plan(build_create_plan(name, cpu, memory_to_mib(mem), net), dry_run=dry_run)


@app.command()
def destroy(
    name: str, dry_run: Annotated[bool, typer.Option("--dry-run")] = False
) -> None:
    """Destroy + undefine a VM and delete its state (tolerant)."""
    run_plan(build_destroy_plan(name), dry_run=dry_run, tolerant=True)


@app.command(name="list")
def list_() -> None:
    """List defined VMs (virsh passthrough)."""
    subprocess.run(["virsh", "list", "--all"], check=False)  # noqa: S603, S607


def main() -> None:
    app()


if __name__ == "__main__":
    main()
