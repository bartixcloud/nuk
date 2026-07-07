"""Unit tests for `nuk update` version resolution + the uv install call.

No network, no uv: `latest_release_tag` and `sh` are monkeypatched.

    uv run pytest tests/test_nuk_update.py
"""

from __future__ import annotations

import nuk
import pytest


def test_norm_ver_parses_and_orders():
    assert nuk.norm_ver("v0.10.0") == (0, 10, 0)
    assert nuk.norm_ver("0.9.0") < nuk.norm_ver("v0.10.0")
    assert nuk.norm_ver("v1.0.0") > nuk.norm_ver("v0.10.0")


def _capture_sh(monkeypatch) -> list[tuple]:
    calls: list[tuple] = []
    monkeypatch.setattr(nuk, "sh", lambda *a, **_k: calls.append(a))
    return calls


def test_update_check_changes_nothing(monkeypatch, capsys):
    monkeypatch.setattr(nuk, "latest_release_tag", lambda repo=nuk.NUK_REPO: "v9.9.9")
    calls = _capture_sh(monkeypatch)
    nuk.cmd_update(to=None, check=True)
    out = capsys.readouterr().out
    assert "v9.9.9" in out
    assert nuk.__version__ in out
    assert calls == []


def test_update_noop_when_up_to_date(monkeypatch, capsys):
    monkeypatch.setattr(nuk, "latest_release_tag", lambda repo=nuk.NUK_REPO: f"v{nuk.__version__}")
    calls = _capture_sh(monkeypatch)
    nuk.cmd_update(to=None, check=False)
    assert "up to date" in capsys.readouterr().out
    assert calls == []


def test_update_installs_latest(monkeypatch):
    monkeypatch.setattr(nuk, "latest_release_tag", lambda repo=nuk.NUK_REPO: "v9.9.9")
    calls = _capture_sh(monkeypatch)
    nuk.cmd_update(to=None, check=False)
    assert calls, "expected `uv tool install` to run"
    argv = calls[0]
    assert argv[:3] == ("uv", "tool", "install")
    assert f"{nuk.NUK_GIT}@v9.9.9" in argv


def test_update_explicit_ref_always_installs(monkeypatch):
    # explicit --to bypasses the up-to-date check (supports pinning + downgrade)
    calls = _capture_sh(monkeypatch)
    nuk.cmd_update(to="v0.0.1", check=False)
    assert calls
    assert f"{nuk.NUK_GIT}@v0.0.1" in calls[0]


def test_update_exits_without_latest(monkeypatch):
    monkeypatch.setattr(nuk, "latest_release_tag", lambda repo=nuk.NUK_REPO: None)
    with pytest.raises(SystemExit):
        nuk.cmd_update(to=None, check=False)
