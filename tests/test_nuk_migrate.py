"""`spec.migrate` — the pre-rollout one-shot migration hook.

Spec: docs/superpowers/specs/2026-10-16-nuk-migrate-hook-design.md
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


_MIGRATE_DEP = {
    "metadata": {"name": "kolbe"},
    "spec": {
        "source": {"repo": "git@github.com:kolbeapp-de/lernstanderfassung.git"},
        "migrate": {"service": "backend", "command": "alembic upgrade head", "timeout": 7},
    },
}


def _migrate(tmp_path, monkeypatch, sh):
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "compose_args", lambda *a: ["docker", "compose", "-p", "kolbe"])
    monkeypatch.setattr(nuk, "sh", sh)
    return nuk.Migrate.model_validate(_MIGRATE_DEP["spec"]["migrate"])


def test_run_migrations_runs_compose_run_and_records(tmp_path, monkeypatch):
    calls: list = []
    m = _migrate(tmp_path, monkeypatch, lambda *cmd, **kw: calls.append((cmd, kw)))
    nuk._run_migrations("kolbe", _MIGRATE_DEP, m, "sha256:cafe")
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


def test_run_migrations_failure_is_fail_closed(tmp_path, monkeypatch):
    def boom(*cmd, **_kw):
        raise subprocess.CalledProcessError(1, cmd)

    m = _migrate(tmp_path, monkeypatch, boom)
    with pytest.raises(subprocess.CalledProcessError):
        nuk._run_migrations("kolbe", _MIGRATE_DEP, m, "sha256:cafe")


def test_run_migrations_timeout_becomes_systemexit(tmp_path, monkeypatch):
    def slow(*cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    m = _migrate(tmp_path, monkeypatch, slow)
    with pytest.raises(SystemExit):
        nuk._run_migrations("kolbe", _MIGRATE_DEP, m, "sha256:cafe")


# --- cmd_apply wiring (Tasks 4) ---------------------------------------------


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


def _bg_yml(*, migrate: bool) -> str:
    mig = 'migrate: {service: backend, command: "alembic upgrade head"}' if migrate else ""
    return f"""\
        apiVersion: nuk/v1
        kind: Deployment
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
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True)), None)
    runs = _migrate_calls(lines)
    assert len(runs) == 1
    assert lines.index(runs[0]) < lines.index(_profile_ups(lines)[0])
    assert nuk.migrated_digest("kolbe") == "sha256:cafe"


def test_cmd_apply_skips_migration_when_digest_unchanged(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: "sha256:cafe")
    doc = _write(tmp_path, _bg_yml(migrate=True))
    nuk.cmd_apply(doc, None)
    lines.clear()
    nuk.cmd_apply(doc, None)
    assert _migrate_calls(lines) == []


def test_cmd_apply_skips_migration_on_rollback(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=True)), None, pin_commit="0" * 40)
    assert _migrate_calls(lines) == []


def test_cmd_apply_without_migrate_never_runs(tmp_path, monkeypatch):
    lines: list[tuple[str, ...]] = []
    _stub_apply(tmp_path, monkeypatch, lines)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: "sha256:cafe")
    nuk.cmd_apply(_write(tmp_path, _bg_yml(migrate=False)), None)
    assert _migrate_calls(lines) == []
