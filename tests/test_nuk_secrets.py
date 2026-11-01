"""sops-encrypted `envFrom[].sopsFile` entries: decrypt into tmpfs, fail closed."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import nuk
import pytest
import yaml
from nuk import secrets
from nuk.models import EnvFrom
from pydantic import ValidationError

PLAINTEXT = "DB_PASSWORD=hunter2-sentinel\nENVIRONMENT=staging\n"

# Stands in for sops: succeeds only when the age key file is the tenant's own,
# like a real ciphertext that was encrypted to a different recipient would not.
FAKE_SOPS = """#!/bin/sh
case "$SOPS_AGE_KEY_FILE" in
  */kolbeapp-de.key) printf '%s' "$FAKE_PLAINTEXT"; exit 0 ;;
esac
printf '%s' "$FAKE_PLAINTEXT"
echo "Failed to get the data key required to decrypt the SOPS file." >&2
exit 128
"""


@pytest.fixture
def host(tmp_path: Path, monkeypatch):
    """A fake host: redirected key/run dirs, a fake `sops` on PATH, a checkout tree."""
    age = tmp_path / "age.d"
    age.mkdir()
    (age / "kolbeapp-de.key").write_text("AGE-SECRET-KEY-x\n")
    (age / "jonesh.key").write_text("AGE-SECRET-KEY-y\n")
    monkeypatch.setattr(nuk.paths, "AGE_DIR", age)
    monkeypatch.setattr(nuk.paths, "RUN_SECRETS", tmp_path / "run")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sops = bin_dir / "sops"
    sops.write_text(FAKE_SOPS)
    sops.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}/usr/bin:/bin")
    monkeypatch.setenv("FAKE_PLAINTEXT", PLAINTEXT)
    tree = tmp_path / "repo"
    (tree / "secrets").mkdir(parents=True)
    (tree / "secrets" / "kolbe-shadow.enc.env").write_text("ciphertext\n")
    return tmp_path


def _entry(path: str = "secrets/kolbe-shadow.enc.env") -> EnvFrom:
    return EnvFrom(sopsFile=path)


def test_renders_to_tmpfs_dir_with_modes(host):
    out = secrets.render("kolbe-shadow", "kolbeapp-de", host / "repo", [_entry()])
    assert out == [host / "run" / "kolbe-shadow" / "kolbe-shadow.env"]
    assert out[0].read_text() == PLAINTEXT
    assert stat.S_IMODE(out[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(out[0].parent.stat().st_mode) == 0o700


def test_foreign_tenant_key_refused_and_nothing_written(host):
    with pytest.raises(secrets.SecretError, match="kolbe-shadow"):
        secrets.render("kolbe-shadow", "jonesh", host / "repo", [_entry()])
    assert not (host / "run" / "kolbe-shadow" / "kolbe-shadow.env").exists()


def test_missing_sops_binary_message(host, monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(secrets.SecretError, match="sops"):
        secrets.render("kolbe-shadow", "kolbeapp-de", host / "repo", [_entry()])


def test_missing_key_file_message(host):
    (host / "age.d" / "kolbeapp-de.key").unlink()
    with pytest.raises(secrets.SecretError, match=r"age\.d.*kolbeapp-de\.key|kolbeapp-de\.key"):
        secrets.render("kolbe-shadow", "kolbeapp-de", host / "repo", [_entry()])


def test_missing_ciphertext_names_the_path(host):
    with pytest.raises(secrets.SecretError, match=r"secrets/absent\.enc\.env"):
        secrets.render(
            "kolbe-shadow", "kolbeapp-de", host / "repo", [_entry("secrets/absent.enc.env")]
        )


def test_rejects_symlink_out_directory(host):
    outside = host / "outside.enc.env"
    outside.write_text("x")
    (host / "repo" / "secrets" / "link.enc.env").symlink_to(outside)
    (host / "repo" / "secrets" / "dir.enc.env").mkdir()
    for rel in ("secrets/link.enc.env", "secrets/dir.enc.env"):
        with pytest.raises(secrets.SecretError):
            secrets.render("kolbe-shadow", "kolbeapp-de", host / "repo", [_entry(rel)])


@pytest.mark.parametrize(
    "bad", ["/etc/x.enc.env", "../x.enc.env", "secrets/../../x.enc.env", "secrets/x.env"]
)
def test_manifest_rejects_dotdot_absolute_and_wrong_suffix(bad):
    with pytest.raises(ValidationError):
        EnvFrom(sopsFile=bad)


def test_secret_value_never_in_error_text(host):
    with pytest.raises(secrets.SecretError) as err:
        secrets.render("kolbe-shadow", "jonesh", host / "repo", [_entry()])
    assert "hunter2-sentinel" not in str(err.value)


def test_entry_needs_exactly_one_of_secretref_sopsfile():
    with pytest.raises(ValidationError):
        EnvFrom()
    with pytest.raises(ValidationError):
        EnvFrom(secretRef="/etc/x.env", sopsFile="secrets/a.enc.env")
    assert EnvFrom(secretRef="/etc/x.env").sops_file is None


def test_platform_source_uses_platform_key(host):
    assert secrets.key_name(None) == "platform"
    assert secrets.key_name("kolbeapp-de") == "kolbeapp-de"


def test_purge_removes_dir(host):
    secrets.render("kolbe-shadow", "kolbeapp-de", host / "repo", [_entry()])
    secrets.purge("kolbe-shadow")
    assert not (host / "run" / "kolbe-shadow").exists()
    secrets.purge("kolbe-shadow")  # idempotent


# --- wiring: apply, compose_args, delete -------------------------------------

SOPS_YML = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: kolbe-shadow}
spec:
  source: {repo: "git@github.com:kolbeapp-de/lernstanderfassung.git"}
  envFrom:
    - sopsFile: secrets/kolbe-shadow.enc.env
"""

_REAL_RESOLVE = nuk.resolve_env_from
_REAL_COMPOSE_ARGS = nuk.compose_args


@pytest.fixture
def proj(host, monkeypatch):
    """project_dir under tmp with the checkout where the `host` fixture put the ciphertext."""
    pdir = host / "proj" / "kolbe-shadow"
    pdir.mkdir(parents=True)
    (host / "repo").rename(pdir / "repo")
    monkeypatch.setattr(nuk, "project_dir", lambda name: host / "proj" / name)
    return pdir


def _spec():
    return nuk.Spec.model_validate(yaml.safe_load(SOPS_YML)["spec"])


def test_apply_refuses_when_sops_file_missing_and_leaves_running_revision(
    host, monkeypatch, tmp_path
):
    from conftest import stub_apply

    lines: list[tuple[str, ...]] = []
    stub_apply(tmp_path, monkeypatch, lines)
    wrote: list[str] = []
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: wrote.append("override"))
    monkeypatch.setattr(nuk, "resolve_env_from", _REAL_RESOLVE)
    (tmp_path / "proj" / "kolbe-shadow" / "repo").mkdir(parents=True)  # a checkout without it
    manifest = tmp_path / "m.yml"
    manifest.write_text(SOPS_YML)
    with pytest.raises(nuk.NukError, match=r"kolbe-shadow.*secrets/kolbe-shadow\.enc\.env"):
        nuk.cmd_apply(manifest, None)
    assert wrote == []
    assert not any("up" in c for c in lines)


def test_compose_args_rerenders_after_run_dir_wiped(proj, host):
    (proj / "tenant").write_text("kolbeapp-de")
    first = _REAL_COMPOSE_ARGS("kolbe-shadow", _spec())
    env_files = [first[i + 1] for i, a in enumerate(first) if a == "--env-file"]
    assert len(env_files) == 1
    shutil.rmtree(host / "run")
    again = _REAL_COMPOSE_ARGS("kolbe-shadow", _spec())
    assert again == first
    assert Path(env_files[0]).read_text(encoding="utf-8") == PLAINTEXT


def test_compose_args_refuses_for_wrong_stored_tenant(proj):
    (proj / "tenant").write_text("jonesh")
    with pytest.raises(nuk.NukError, match="kolbe-shadow"):
        _REAL_COMPOSE_ARGS("kolbe-shadow", _spec())


def test_delete_purges_plaintext(proj, host, monkeypatch):
    secrets.render("kolbe-shadow", "kolbeapp-de", proj / "repo", _spec().env_from)
    assert (host / "run" / "kolbe-shadow").exists()
    monkeypatch.setattr(nuk, "_router_file", lambda name: host / f"{name}.yml")
    nuk.cmd_delete("kolbe-shadow", purge=False)
    assert not (host / "run" / "kolbe-shadow").exists()


def test_delete_still_runs_down_when_secrets_cannot_render(proj, host, monkeypatch):
    (proj / "manifest.yml").write_text(SOPS_YML)
    (proj / "tenant").write_text("jonesh")  # key mismatch -> render fails
    calls: list[list[str]] = []
    real_run = subprocess.run

    def fake_run(cmd, **kw):
        if cmd[0] == "docker":
            calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0)
        return real_run(cmd, **kw)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(nuk, "_router_file", lambda name: host / f"{name}.yml")
    nuk.cmd_delete("kolbe-shadow", purge=False)
    assert any(c[-2:] == ["down", "-v"] and "kolbe-shadow" in c for c in calls)


def test_legacy_secretref_behaviour_unchanged(tmp_path):
    present = tmp_path / "present.env"
    present.write_text("A=1\n")
    spec = nuk.Spec.model_validate(
        {"envFrom": [{"secretRef": str(present)}, {"secretRef": str(tmp_path / "gone.env")}]}
    )
    assert _REAL_RESOLVE(spec) == [str(present)]
