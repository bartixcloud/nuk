"""`spec.strategy` — parsing the blue-green deployment strategy.

Spec: docs/superpowers/plans/2026-10-11-nuk-deploy-strategies.md (Task 4).
"""

from __future__ import annotations

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
