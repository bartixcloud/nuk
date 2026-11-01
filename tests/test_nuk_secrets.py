"""sops-encrypted `envFrom[].sopsFile` entries: decrypt into tmpfs, fail closed."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

import nuk
import pytest
from nuk import secrets
from nuk.models import EnvFrom
from pydantic import ValidationError

if TYPE_CHECKING:
    from pathlib import Path

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
