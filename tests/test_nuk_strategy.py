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
