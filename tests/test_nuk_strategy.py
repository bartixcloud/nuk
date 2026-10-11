"""`spec.strategy` — parsing the blue-green deployment strategy.

Spec: docs/superpowers/plans/2026-10-11-nuk-deploy-strategies.md (Task 4).
"""

from __future__ import annotations

import subprocess
import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import nuk


def _write(tmp_path: Path, body: str, name: str = "m.yml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


STRATEGY_YML = """\
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: kolbe}
    spec:
      placement: {role: app}
      source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
      strategy:
        type: blue-green
        health: {service: backend, path: /health}
        keepPrevious: true
"""

NO_STRATEGY_YML = """\
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: kolbe}
    spec:
      placement: {role: app}
      source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
"""


def test_load_parses_blue_green_strategy(tmp_path):
    dep = nuk.load(_write(tmp_path, STRATEGY_YML))
    assert dep.spec.strategy.type == "blue-green"
    assert dep.spec.strategy.health.service == "backend"
    assert dep.spec.strategy.health.path == "/health"
    assert dep.spec.strategy.keep_previous is True


def test_load_parses_strategy_defaults(tmp_path):
    dep = nuk.load(_write(tmp_path, STRATEGY_YML))
    assert dep.spec.strategy.drain == 30
    assert dep.spec.strategy.health.port is None
    assert dep.spec.strategy.health.timeout == 120
    assert dep.spec.strategy.health.interval == pytest.approx(2.0)


def test_load_without_strategy_is_none(tmp_path):
    dep = nuk.load(_write(tmp_path, NO_STRATEGY_YML))
    assert dep.spec.strategy is None


def test_strategy_rejects_unknown_type(tmp_path):
    with pytest.raises(SystemExit):
        nuk.load(_write(tmp_path, STRATEGY_YML.replace("blue-green", "canary")))


def test_active_colour_defaults_to_blue(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    assert nuk.active_colour("kolbe") == "blue"
    assert nuk.idle_colour("blue") == "green"


def test_record_active_colour_persists(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    nuk.record_active_colour("kolbe", "green")
    assert nuk.active_colour("kolbe") == "green"
    assert nuk.idle_colour("green") == "blue"


def test_router_dialect_defaults_to_edge_when_unset(tmp_path, monkeypatch):
    """An app with no persisted dialect marker is an edge deployment."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path)
    assert nuk.router_dialect("kolbe") == "edge"


def test_await_healthy_returns_once_the_container_answers(monkeypatch):
    """The gate polls the idle colour and returns on the first zero exit."""
    calls: list[tuple[str, ...]] = []

    def exec_(*cmd: str) -> None:
        calls.append(cmd)
        if len(calls) < 3:
            raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(nuk.time, "sleep", lambda _s: None)

    nuk.await_healthy(
        "kolbe-backend-green", "/health", timeout=120, interval=2.0, exec_=exec_
    )

    assert len(calls) == 3
    assert calls[0][:3] == ("docker", "exec", "kolbe-backend-green")
    probe = calls[0][-1]
    assert "/health" in probe
    assert "8000" in probe


def test_await_healthy_raises_when_the_container_never_answers(monkeypatch):
    """A never-zero probe raises ValueError once the fake clock passes `timeout`."""
    clock = {"now": 0.0}

    def fake_monotonic() -> float:
        return clock["now"]

    def fake_sleep(seconds: float) -> None:
        clock["now"] += seconds

    def exec_(*cmd: str) -> None:
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(nuk.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(nuk.time, "sleep", fake_sleep)

    with pytest.raises(ValueError, match="did not answer"):
        nuk.await_healthy(
            "kolbe-backend-green", "/health", timeout=5, interval=2.0, exec_=exec_
        )
    assert clock["now"] >= 5


def test_await_healthy_probes_the_configured_port(monkeypatch):
    """A non-default `port` is threaded into the probe URL, not hardcoded 8000."""
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(nuk.time, "sleep", lambda _s: None)

    nuk.await_healthy(
        "kolbe-backend-green",
        "/health",
        timeout=5,
        interval=1.0,
        port=9000,
        exec_=lambda *cmd: calls.append(cmd),
    )

    assert "localhost:9000/health" in calls[0][-1]


# --- blue-green apply path (Task 7) --------------------------------------------------


def _blue_green_yml(
    *,
    keep_previous: bool,
    port: int | None = None,
    health_service: str = "backend",
    ingress_service: str = "frontend",
    ingress_port: int = 80,
) -> str:
    health = f"{{service: {health_service}, path: /health"
    if port is not None:
        health += f", port: {port}"
    health += "}"
    keep = "true" if keep_previous else "false"
    return textwrap.dedent(f"""\
        apiVersion: nuk/v1
        kind: Deployment
        metadata: {{name: kolbe}}
        spec:
          placement: {{role: app}}
          source: {{repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}}
          ingress:
            - {{host: kolbe.astrojones.de, service: {ingress_service}, port: {ingress_port}}}
          strategy:
            type: blue-green
            health: {health}
            keepPrevious: {keep}
    """).lstrip()


def _stub_apply(
    tmp_path: Path,
    monkeypatch,
    lines: list[tuple[str, ...]],
    *,
    real_override: bool = False,
) -> None:
    """Stub everything cmd_apply touches outside the tree; record `sh` calls."""
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    if not real_override:
        monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["compose", "-p", "kolbe"])
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: lines.append(cmd))


def _profile_up(lines: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [c for c in lines if "--profile" in c and "up" in c]


def test_blue_green_apply_rolls_out_idle_then_flips_then_drains(tmp_path, monkeypatch):
    """Idle up -> health -> flip -> record -> drain, in that order."""
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=False))
    nuk.cmd_apply(doc, None)

    ups = _profile_up(lines)
    execs = [c for c in lines if c[:2] == ("docker", "exec")]
    downs = [c for c in lines if "down" in c]

    assert ups == [("compose", "-p", "kolbe", "--profile", "green", "up", "-d")]
    assert len(execs) == 1
    assert execs[0][:3] == ("docker", "exec", "kolbe-backend-green-1")
    assert downs == [
        ("compose", "-p", "kolbe", "--profile", "blue", "down", "backend-blue", "frontend-blue")
    ]
    assert lines.index(ups[0]) < lines.index(execs[0]) < lines.index(downs[0])
    assert nuk.active_colour("kolbe") == "green"
    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-green-1:80"


def test_blue_green_apply_keeps_the_previous_colour_when_asked(tmp_path, monkeypatch):
    """`keepPrevious: true` skips the drain but still rolls out and flips."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=True))
    nuk.cmd_apply(doc, None)

    assert _profile_up(lines) == [("compose", "-p", "kolbe", "--profile", "green", "up", "-d")]
    assert not any("down" in c for c in lines)
    assert nuk.active_colour("kolbe") == "green"


def test_blue_green_apply_probes_the_health_port(tmp_path, monkeypatch):
    """`health.port` reaches the probe URL (`await_healthy` is not left on 8000)."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=True, port=9000))
    nuk.cmd_apply(doc, None)

    execs = [c for c in lines if c[:2] == ("docker", "exec")]
    assert "localhost:9000/health" in execs[0][-1]


def test_blue_green_probe_target_matches_the_router_backend(tmp_path, monkeypatch):
    """The probe and the router URL name the SAME container.

    Both must use docker compose's default `<name>-<service>-<colour>-1` form, so
    when health and ingress name the same service the probe's `docker exec` target
    has to equal the router URL host. The expected name is derived from
    `_container_name` (not the code's literal) and then cross-asserted router-vs-
    probe, so a stub that merely echoes a wrong probe can't pass.
    """
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(
        tmp_path,
        _blue_green_yml(
            keep_previous=True,
            health_service="backend",
            ingress_service="backend",
            ingress_port=8080,
        ),
    )
    nuk.cmd_apply(doc, None)

    execs = [c for c in lines if c[:2] == ("docker", "exec")]
    probe_target = execs[0][2]
    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    router_target = url.removeprefix("http://").rsplit(":", 1)[0]

    assert probe_target == nuk._container_name("kolbe", "backend", "green")
    assert probe_target == router_target


def test_blue_green_drains_every_published_service(tmp_path, monkeypatch):
    """Drain targets come from the manifest, not a hardcoded backend/frontend pair."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(
        tmp_path,
        _blue_green_yml(
            keep_previous=False,
            health_service="api",
            ingress_service="web",
            ingress_port=8080,
        ),
    )
    nuk.cmd_apply(doc, None)

    downs = [c for c in lines if "down" in c]
    assert downs == [
        ("compose", "-p", "kolbe", "--profile", "blue", "down", "api-blue", "web-blue")
    ]


NON_STRATEGY_INGRESS_YML = """\
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: kolbe}
    spec:
      placement: {role: app}
      source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
      ingress:
        - {host: kolbe.astrojones.de, service: frontend, port: 80}
"""


ROUTER_FACILITY_YML = """\
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: router}
    spec:
      placement: {role: app}
"""


def _with_router_facility(tmp_path: Path) -> None:
    """Put the fleet-wide `router` facility in the tree, switching router mode on."""
    facilities = tmp_path / "facilities"
    facilities.mkdir(parents=True, exist_ok=True)
    (facilities / "router.yml").write_text(
        textwrap.dedent(ROUTER_FACILITY_YML).lstrip(), encoding="utf-8"
    )


def test_router_mode_blue_green_apply_writes_a_mesh_router(tmp_path, monkeypatch):
    """In router mode the colour flip writes the app-host file router in the mesh dialect.

    The app host's Traefik (the `router` facility) listens on the private `mesh`
    entrypoint with no TLS and no edge `global.yml`, so an edge-dialect file it
    cannot serve is dropped (C1). The flip must name the idle colour container.
    """
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    _with_router_facility(tmp_path)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=True))
    nuk.cmd_apply(doc, None)

    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    entry = router["http"]["routers"]["kolbe-0"]
    assert entry["entryPoints"] == ["mesh"]
    assert "tls" not in entry
    assert not any("maintenance-errors" in m for m in entry.get("middlewares", []))
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-green-1:80"


def test_router_mode_plain_apply_writes_a_mesh_router(tmp_path, monkeypatch):
    """A non-blue-green app on a router-mode host authors its own mesh router.

    Without router mode an app host UNLINKS the file (the edge renders it, spec
    §6); in router mode the app host IS the router, so it must write it itself —
    in the mesh dialect it can actually serve.
    """
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    _with_router_facility(tmp_path)
    doc = _write(tmp_path, NON_STRATEGY_INGRESS_YML)
    nuk.cmd_apply(doc, None)

    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    entry = router["http"]["routers"]["kolbe-0"]
    assert entry["entryPoints"] == ["mesh"]
    assert "tls" not in entry
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-1:80"


def test_router_mode_override_targets_colour_services_on_the_edge_network(tmp_path, monkeypatch):
    """In router mode the override must name the COLOUR services on the shared `edge`.

    The app-host router resolves each backend by its compose DNS name
    (`<name>-<service>-<colour>-1`) over the shared `edge` network, so the override
    must (a) key on the colour services (not the phantom base names), (b) join the
    EXTERNAL `edge` network, (c) publish NO port (the router dials the container, not
    a host port), and (d) still inject the DB creds. Non-router output is unchanged.
    """
    import yaml

    db_env = "/opt/nuklaut/secrets/kolbe-db.env"
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines, real_override=True)
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: db_env)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: ["backend"])
    _with_router_facility(tmp_path)
    doc = _write(
        tmp_path,
        _blue_green_yml(keep_previous=True, ingress_service="backend", ingress_port=8000),
    )
    nuk.cmd_apply(doc, None)

    ov = yaml.safe_load(
        (tmp_path / "proj" / "kolbe" / "compose.override.yml").read_text(encoding="utf-8")
    )
    assert "backend-blue" in ov["services"]
    assert "backend-green" in ov["services"]
    assert "backend" not in ov["services"]
    svc = ov["services"]["backend-blue"]
    assert "edge" in svc["networks"]  # joins the router's shared network
    assert "ports" not in svc  # no published port: the router dials the container
    assert svc["env_file"] == [db_env]  # the DB creds still reach the colour service
    assert ov["networks"]["edge"] == {"external": True}


def test_apply_without_strategy_keeps_the_plain_up(tmp_path, monkeypatch):
    """A non-strategy deployment still does a single `up -d`, no profile, no flip."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(tmp_path, NON_STRATEGY_INGRESS_YML)
    nuk.cmd_apply(doc, None)

    ups = [c for c in lines if c[-2:] == ("up", "-d")]
    assert ups == [("compose", "-p", "kolbe", "up", "-d")]
    assert not any("--profile" in c for c in lines)
    assert not any(c[:2] == ("docker", "exec") for c in lines)
    assert nuk.active_colour("kolbe") == "blue"  # never recorded


# --- blue-green rollback (Task 8) ----------------------------------------------------


def _persist_blue_green(*, keep_previous: bool) -> None:
    """Write the manifest `cmd_rollback` reads back (cmd_apply's persist is stubbed)."""
    path = nuk._manifest_file("kolbe")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_blue_green_yml(keep_previous=keep_previous), encoding="utf-8")


def test_blue_green_rollback_flips_the_router_back_and_brings_the_colour_up(
    tmp_path, monkeypatch
):
    """Rollback after an apply flips active→previous, bringing it back up first.

    The apply drained blue (keepPrevious=false), so rollback must bring blue's
    idle profile back up, health-gate it, flip the router to blue, and record it.
    """
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=False))
    nuk.cmd_apply(doc, None)
    assert nuk.active_colour("kolbe") == "green"
    _persist_blue_green(keep_previous=False)

    rolled: list[tuple[str, ...]] = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: rolled.append(cmd))
    nuk.cmd_rollback("kolbe", to=None, show=False)

    ups = _profile_up(rolled)
    execs = [c for c in rolled if c[:2] == ("docker", "exec")]
    assert ups == [("compose", "-p", "kolbe", "--profile", "blue", "up", "-d")]
    assert execs[0][:3] == ("docker", "exec", "kolbe-backend-blue-1")
    assert rolled.index(ups[0]) < rolled.index(execs[0])  # up precedes the health probe
    assert nuk.active_colour("kolbe") == "blue"
    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-blue-1:80"
    entry = router["http"]["routers"]["kolbe-0"]
    assert entry["entryPoints"] == ["websecure"]  # non-router mode: the edge dialect
    assert entry["tls"] == {"certResolver": "letsencrypt"}


def test_router_mode_blue_green_rollback_writes_a_mesh_router(tmp_path, monkeypatch):
    """The rollback flip replays the dialect the apply persisted, not a guessed one.

    Rollback builds its context from the persisted manifest, whose tree ships no
    `facilities/`, so router mode is undetectable at rollback time. The apply
    records the dialect beside `active-colour`, and the flip reads it back — so a
    router-mode app keeps its mesh-dialect router instead of dropping an edge file
    the app host's Traefik (the `router` facility) cannot serve (C1).
    """
    import yaml

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    _with_router_facility(tmp_path)
    doc = _write(tmp_path, _blue_green_yml(keep_previous=True))
    nuk.cmd_apply(doc, None)
    assert nuk.router_dialect("kolbe") == "mesh"  # the apply persisted it
    _persist_blue_green(keep_previous=True)

    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: None)
    nuk.cmd_rollback("kolbe", to=None, show=False)

    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    entry = router["http"]["routers"]["kolbe-0"]
    assert entry["entryPoints"] == ["mesh"]
    assert "tls" not in entry
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-blue-1:80"


def test_blue_green_rollback_refuses_without_a_persisted_manifest(tmp_path, monkeypatch):
    """The colour flip needs the manifest to name the services; fail closed if gone."""
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    with pytest.raises(SystemExit, match=r"manifest\.yml"):
        nuk.cmd_rollback("kolbe", to=None, show=False)


def test_rollback_to_an_explicit_index_does_not_flip_a_blue_green_app(tmp_path, monkeypatch):
    """`--to N` re-applies release N by digest; it must NOT colour-flip.

    The flip is only for `to is None`; an explicit index is the digest path,
    even on a blue-green deployment (a silent flip would be a surprising,
    side-effecting regression).
    """
    import json

    deployments = tmp_path / "deploys"
    releases = tmp_path / "releases"
    (deployments / "kolbe").mkdir(parents=True)
    releases.mkdir()
    (releases / "kolbe.jsonl").write_text(
        json.dumps(
            {"commit": "a" * 40, "imageDigest": "sha256:1", "appliedAt": "2026-01-01T00:00:00.000Z"}
        )
        + "\n",
        encoding="utf-8",
    )
    (deployments / "kolbe" / "manifest.yml").write_text(
        _blue_green_yml(keep_previous=True), encoding="utf-8"
    )
    monkeypatch.setattr(nuk, "RELEASES", releases)
    monkeypatch.setattr(nuk, "DEPLOYS", deployments)
    monkeypatch.setattr(nuk, "project_dir", lambda name: deployments / name)
    seen: dict[str, str | None] = {}
    monkeypatch.setattr(
        nuk,
        "cmd_apply",
        lambda path, repo_path, *, pin_commit=None, pin_digest=None: seen.update(
            pin_digest=pin_digest, pin_commit=pin_commit
        ),
    )
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: calls.append(cmd))

    nuk.cmd_rollback("kolbe", to=0, show=False)

    assert seen["pin_digest"] == "sha256:1"
    assert seen["pin_commit"] == "a" * 40
    assert calls == []  # no flip: no compose up, no router write, no colour record


def test_blue_green_rollback_refuses_without_a_recorded_colour(tmp_path, monkeypatch):
    """No apply ever recorded a colour, so there is no previous colour to flip to.

    `active_colour` defaults to blue; without this guard the flip would bring
    up a colour that never ran and record it active.
    """
    deployments = tmp_path / "deploys"
    (deployments / "kolbe").mkdir(parents=True)
    (deployments / "kolbe" / "manifest.yml").write_text(
        _blue_green_yml(keep_previous=True), encoding="utf-8"
    )
    monkeypatch.setattr(nuk, "RELEASES", tmp_path / "releases")
    monkeypatch.setattr(nuk, "DEPLOYS", deployments)
    monkeypatch.setattr(nuk, "project_dir", lambda name: deployments / name)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: calls.append(cmd))

    with pytest.raises(SystemExit, match=r"no previous release recorded"):
        nuk.cmd_rollback("kolbe", to=None, show=False)

    assert calls == []
    assert nuk.active_colour("kolbe") == "blue"  # nothing was flipped or recorded


def test_blue_green_rollback_flips_back_even_when_keep_previous_kept_it(tmp_path, monkeypatch):
    """A kept previous colour is already up; rollback still flips to it."""
    import yaml

    deployments = tmp_path / "deploys"
    (deployments / "kolbe").mkdir(parents=True)
    (deployments / "kolbe" / "manifest.yml").write_text(
        _blue_green_yml(keep_previous=True), encoding="utf-8"
    )
    monkeypatch.setattr(nuk, "RELEASES", tmp_path / "releases")
    monkeypatch.setattr(nuk, "DEPLOYS", deployments)
    (tmp_path / "dynamic").mkdir()
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "project_dir", lambda name: deployments / name)
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["compose", "-p", "kolbe"])
    nuk.record_active_colour("kolbe", "green")
    rolled: list[tuple[str, ...]] = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd, **_k: rolled.append(cmd))

    nuk.cmd_rollback("kolbe", to=None, show=False)

    assert _profile_up(rolled) == [("compose", "-p", "kolbe", "--profile", "blue", "up", "-d")]
    assert nuk.active_colour("kolbe") == "blue"
    router = yaml.safe_load((tmp_path / "dynamic" / "kolbe.yml").read_text(encoding="utf-8"))
    url = router["http"]["services"]["kolbe-0"]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://kolbe-frontend-blue-1:80"
