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


def _stub_apply(tmp_path: Path, monkeypatch, lines: list[tuple[str, ...]]) -> None:
    """Stub everything cmd_apply touches outside the tree; record `sh` calls."""
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
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
