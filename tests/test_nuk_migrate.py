"""`spec.migrate` — the pre-rollout one-shot migration hook.

Spec: docs/superpowers/specs/2026-10-16-nuk-migrate-hook-design.md
"""

from __future__ import annotations

import subprocess
import textwrap
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from conftest import stub_apply as _stub_apply

if TYPE_CHECKING:
    from pathlib import Path

import nuk


def _write(tmp_path: Path, body: str, name: str = "m.yml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


def _after(argv: tuple[str, ...], flag: str) -> str:
    """The token that follows `flag` in an argv — reads positionally, not by index."""
    return argv[argv.index(flag) + 1]


MIGRATE_YML = """\
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: kolbe}
    spec:
      source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
      migrate: {service: backend, command: "alembic upgrade head"}
"""

NO_MIGRATE_YML = """\
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: kolbe}
    spec:
      source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
"""


def test_load_parses_migrate(tmp_path):
    dep = nuk.load(_write(tmp_path, MIGRATE_YML))
    assert dep.spec.migrate.service == "backend"
    assert dep.spec.migrate.command == "alembic upgrade head"
    assert dep.spec.migrate.timeout == 300


def test_load_without_migrate_is_none(tmp_path):
    dep = nuk.load(_write(tmp_path, NO_MIGRATE_YML))
    assert dep.spec.migrate is None


def test_migrated_digest_defaults_none_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    assert nuk.migrated_digest("kolbe") is None
    nuk.record_migrated_digest("kolbe", "sha256:deadbeef")
    assert nuk.migrated_digest("kolbe") == "sha256:deadbeef"


_MIGRATE = {"service": "backend", "command": "alembic upgrade head", "timeout": 7}
_MIGRATE_SPEC = nuk.Spec.model_validate(
    {
        "source": {"repo": "git@github.com:kolbeapp-de/lernstanderfassung.git"},
        "migrate": _MIGRATE,
    }
)


def _migrate(tmp_path, monkeypatch, sh):
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "compose_args", lambda *a: ["docker", "compose", "-p", "kolbe"])
    monkeypatch.setattr(nuk, "sh", sh)
    return nuk.Migrate.model_validate(_MIGRATE)


def test_run_migrations_runs_compose_run_and_records(tmp_path, monkeypatch):
    calls: list = []
    m = _migrate(tmp_path, monkeypatch, lambda *cmd, **kw: calls.append((cmd, kw)))
    nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, None, "sha256:cafe")
    assert calls[0][0] == (
        "docker",
        "compose",
        "-p",
        "kolbe",
        "run",
        "--rm",
        "--no-deps",
        "backend",
        "alembic",
        "upgrade",
        "head",
    )
    assert calls[0][1] == {"timeout": 7}
    assert nuk.migrated_digest("kolbe") == "sha256:cafe"


def test_run_migrations_suffixes_the_idle_colour_for_blue_green(tmp_path, monkeypatch):
    """A blue-green compose's services are colour-suffixed (`backend-blue`).

    The migration targets the idle colour — the one the rollout is about to bring
    up — exactly as `strategy.health.service` is colour-suffixed by the probe.
    """
    calls: list = []
    m = _migrate(tmp_path, monkeypatch, lambda *cmd, **kw: calls.append((cmd, kw)))
    strategy = nuk.Strategy.model_validate(
        {"type": "blue-green", "health": {"service": "backend", "path": "/health"}}
    )
    nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, strategy, "sha256:cafe")
    argv = calls[0][0]
    assert _after(argv, "--profile") == "green"
    assert _after(argv, "--no-deps") == "backend-green"


def test_run_migrations_failure_is_fail_closed(tmp_path, monkeypatch):
    def boom(*cmd, **_kw):
        raise subprocess.CalledProcessError(1, cmd)

    m = _migrate(tmp_path, monkeypatch, boom)
    with pytest.raises(SystemExit):
        nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, None, "sha256:cafe")
    assert nuk.migrated_digest("kolbe") is None


def test_run_migrations_timeout_stops_the_container(tmp_path, monkeypatch):
    """A timeout must stop the migration container, not just the compose client."""
    calls: list = []

    def slow(*cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    def fake_run(*cmd, **kw):  # noqa: ARG001
        calls.append(cmd)
        return type("P", (), {"stdout": "", "returncode": 0})()

    m = _migrate(tmp_path, monkeypatch, slow)
    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    with pytest.raises(SystemExit):
        nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, None, "sha256:cafe")
    assert any(tuple(c[0][4:7]) == ("rm", "-sf", "backend") for c in calls)


def test_rollout_key_uses_the_configured_image_not_the_running_one(monkeypatch):
    """`compose images` reports the running (old) release — the gate must not use it."""
    monkeypatch.setattr(nuk, "_compose_images", lambda name, raw: ["ghcr.io/x/backend:v_new"])
    monkeypatch.setattr(
        nuk.subprocess,
        "run",
        lambda *a, **k: type("P", (), {"stdout": "sha256:new\n", "returncode": 0})(),
    )
    assert nuk._rollout_key("kolbe", nuk.Spec()) == "sha256:new"


def test_rollout_key_is_none_when_unresolvable(monkeypatch):
    """An unresolvable key must not collapse to the `-` revision sentinel."""
    monkeypatch.setattr(nuk, "_compose_images", lambda name, raw: [])
    monkeypatch.setattr(nuk, "_applied_revision", lambda name: "-")
    assert nuk._rollout_key("kolbe", nuk.Spec()) is None
    monkeypatch.setattr(nuk, "_applied_revision", lambda name: "abc1234")
    assert nuk._rollout_key("kolbe", nuk.Spec()) == "abc1234"


# --- cmd_apply wiring (Tasks 4) ---------------------------------------------
# `_stub_apply` (the shared `cmd_apply` perimeter stub) lives in tests/conftest.py


def _bg_yml(*, migrate: bool, kind: str = "Deployment") -> str:
    mig = 'migrate: {service: backend, command: "alembic upgrade head"}' if migrate else ""
    return f"""\
        apiVersion: nuk/v1
        kind: {kind}
        metadata: {{name: kolbe}}
        spec:
          placement: {{role: app}}
          source: {{repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}}
          ingress:
            - {{host: kolbe.astrojones.de, service: frontend, port: 80}}
          strategy:
            type: blue-green
            health: {{service: backend, path: /health}}
            keepPrevious: true
          {mig}
    """


def _migrate_calls(lines: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [c for c in lines if "run" in c and "--no-deps" in c]


def _profile_ups(lines: list[tuple[str, ...]]) -> list[tuple[str, ...]]:
    return [c for c in lines if "--profile" in c and "up" in c]


def test_cmd_apply_runs_migration_before_idle_up(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True)), None)
    runs = _migrate_calls(lines)
    assert len(runs) == 1
    assert lines.index(runs[0]) < lines.index(_profile_ups(lines)[0])
    assert nuk.migrated_digest("kolbe") == "sha256:cafe"


def test_cmd_apply_skips_migration_when_digest_unchanged(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    doc = _write(tmp_path, _bg_yml(migrate=True))
    nuk.cmd_apply(doc, None)
    lines.clear()
    nuk.cmd_apply(doc, None)
    assert _migrate_calls(lines) == []


def test_cmd_apply_skips_migration_on_a_digest_rollback(tmp_path, monkeypatch):
    """Only the digest-path rollback skips — it is the caller that passes `pin_digest`.

    A blue-green colour flip never reaches `cmd_apply` at all; the loop's ordinary
    signed apply passes `pin_commit`, which must NOT skip (see the next test).
    """
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    monkeypatch.setattr(nuk, "_pin_image", lambda *_a, **_k: None)
    nuk.cmd_apply(
        _write(tmp_path, _bg_yml(migrate=True)),
        None,
        pin_digest="ghcr.io/kolbeapp-de/lernstanderfassung/backend@sha256:cafe",
    )
    assert _migrate_calls(lines) == []


def test_cmd_apply_runs_migration_on_a_signed_apply(tmp_path, monkeypatch):
    """A signed deployment is applied with `pin_commit` set and STILL migrates."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True)), None, pin_commit="0" * 40)
    assert len(_migrate_calls(lines)) == 1


def test_cmd_apply_without_migrate_never_runs(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=False)), None)
    assert _migrate_calls(lines) == []


def test_cmd_apply_migration_failure_aborts_before_the_idle_up(tmp_path, monkeypatch):
    """Fail-closed: a failed migration must suppress the rollout entirely."""
    failures: list[tuple[str, ...]] = []

    def sh(*cmd, **_kw):
        if "run" in cmd and "--no-deps" in cmd:
            raise subprocess.CalledProcessError(1, cmd)
        failures.append(cmd)

    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "sh", sh)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    with pytest.raises(SystemExit):
        nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True)), None)
    assert _profile_ups(lines) == []
    assert nuk.migrated_digest("kolbe") is None


# --- model validation --------------------------------------------------------


def test_migrate_rejects_a_blank_service_or_command():
    """A blank field is a config error, not a silent run with the image's own CMD."""
    with pytest.raises(ValidationError):
        nuk.Migrate.model_validate({"service": "", "command": "alembic upgrade head"})
    with pytest.raises(ValidationError):
        nuk.Migrate.model_validate({"service": "backend", "command": "   "})


def test_migrate_rejects_a_non_positive_timeout():
    with pytest.raises(ValidationError):
        nuk.Migrate.model_validate({"service": "backend", "command": "x", "timeout": 0})


def test_migrate_strips_surrounding_whitespace():
    m = nuk.Migrate.model_validate({"service": " backend ", "command": " alembic upgrade head "})
    assert m.service == "backend"
    assert m.command == "alembic upgrade head"


# --- profile + kind ----------------------------------------------------------


def test_run_migrations_without_a_strategy_carries_no_profile(tmp_path, monkeypatch):
    calls: list = []
    m = _migrate(tmp_path, monkeypatch, lambda *cmd, **kw: calls.append((cmd, kw)))
    nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, None, "sha256:cafe")
    assert "--profile" not in calls[0][0]


def test_run_migrations_enables_the_idle_profile(tmp_path, monkeypatch):
    """`run` on a colour-profile service carries `--profile <idle>` explicitly.

    Redundant where Compose enables the named service's profile implicitly, but
    it removes the dependence on that (undocumented-in-our-compose) behaviour.
    """
    calls: list = []
    m = _migrate(tmp_path, monkeypatch, lambda *cmd, **kw: calls.append((cmd, kw)))
    strategy = nuk.Strategy.model_validate(
        {"type": "blue-green", "health": {"service": "backend", "path": "/health"}}
    )
    nuk._run_migrations("kolbe", _MIGRATE_SPEC, m, strategy, "sha256:cafe")
    assert _after(calls[0][0], "--profile") == "green"


def test_cmd_apply_ignores_migrate_on_a_facility(tmp_path, monkeypatch):
    """`spec.migrate` is a Deployment concern (spec §3); a Facility never migrates."""
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_configured_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True, kind="Facility")), None)
    assert _migrate_calls(lines) == []
