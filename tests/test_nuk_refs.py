"""The per-deployment-ref feature: `spec.source.unsigned` and the two-ref sync.

A non-prod/test deployment declares that it deploys the branch head without a
signed `v*` tag (`spec.source.unsigned`); the converge loop syncs each source at
BOTH the signed tag and the branch head and archives both trees. Tasks 9-12 build
this up; the model field lands first, the fetch/archive here.

Real git repos with real SSH-signed tags in tmp_path — no mocks on the crypto,
because the crypto IS the security boundary (spec §7.3). No network.

    uv run pytest tests/test_nuk_refs.py
"""

from __future__ import annotations

import subprocess

import nuk
import pytest
import yaml


@pytest.fixture(autouse=True)
def _hermetic_git(tmp_path, monkeypatch):
    """Neutralize the developer's global/system git config for every test."""
    nowhere = str(tmp_path / "no-such-gitconfig")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", nowhere)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", nowhere)


def _run(*cmd, cwd=None):
    """Run a command, raising with captured output on failure."""
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def _sign_tag(repo, pubkey, tag):
    """Create an SSH-signed annotated tag at HEAD."""
    _run(
        "git",
        "-c",
        "gpg.format=ssh",
        "-c",
        f"user.signingkey={pubkey}",
        "tag",
        "-s",
        tag,
        "-m",
        tag,
        cwd=repo,
    )


@pytest.fixture
def two_ref_origin(tmp_path):
    """A bare origin: signed `v1.0.0` on `main`, one newer commit on `main` after it."""
    key = tmp_path / "signing"
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "astrojones", "-f", str(key))
    signers_dir = tmp_path / "allowed_signers.d"
    signers_dir.mkdir()
    (signers_dir / "astrojones").write_text(
        f"astrojones {key.with_suffix('.pub').read_text(encoding='utf-8').strip()}\n",
        encoding="utf-8",
    )
    work = tmp_path / "work"
    work.mkdir()
    _run("git", "init", "-q", "-b", "main", cwd=work)
    _run("git", "config", "user.email", "t@example.invalid", cwd=work)
    _run("git", "config", "user.name", "T", cwd=work)
    (work / "f").write_text("1\n", encoding="utf-8")
    _run("git", "add", "f", cwd=work)
    _run("git", "commit", "-qm", "one", cwd=work)
    _sign_tag(work, key.with_suffix(".pub"), "v1.0.0")
    tag_sha = _run("git", "rev-parse", "HEAD", cwd=work).stdout.strip()
    (work / "f").write_text("2\n", encoding="utf-8")
    _run("git", "commit", "-qam", "two", cwd=work)
    branch_sha = _run("git", "rev-parse", "HEAD", cwd=work).stdout.strip()
    origin = tmp_path / "origin.git"
    _run("git", "clone", "--bare", "-q", str(work), str(origin))
    return origin, signers_dir, tag_sha, branch_sha


def _src(origin, apply=("deployments",)):
    return nuk.SourceEntry(
        name="astrojones", repo=str(origin), deploy_key="/nonexistent/key", apply=list(apply)
    )


def _manifest(tmp_path, source: dict) -> nuk.Deployment | nuk.Facility:
    path = tmp_path / "deployment.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "nuk/v1",
                "kind": "Deployment",
                "metadata": {"name": "app"},
                "spec": {"source": source},
            }
        ),
        encoding="utf-8",
    )
    return nuk.load(path)


def test_source_unsigned_true_parses(tmp_path):
    manifest = _manifest(tmp_path, {"repo": "https://example.com/app.git", "unsigned": True})
    assert manifest.spec.source.unsigned is True


def test_source_unsigned_defaults_false(tmp_path):
    manifest = _manifest(tmp_path, {"repo": "https://example.com/app.git"})
    assert manifest.spec.source.unsigned is False


def test_source_unsigned_round_trips():
    source = nuk.Source(repo="r", unsigned=True)
    assert nuk.Source.model_validate(source.model_dump()).unsigned is True


def test_sync_source_returns_the_tag_sha_and_the_branch_head(two_ref_origin, tmp_path):
    """Task 10: both refs come back — the signed tag and the newer branch head."""
    origin, signers_dir, tag_sha, branch_sha = two_ref_origin
    tag, got_tag_sha, got_branch_sha = nuk.sync_source(
        _src(origin), signers_dir, tmp_path / "state"
    )
    assert tag == "v1.0.0"
    assert got_tag_sha == tag_sha
    assert got_branch_sha == branch_sha
    assert got_tag_sha != got_branch_sha


def test_sync_source_refuses_a_repo_with_no_signed_tag(two_ref_origin, tmp_path):
    """The tag path stays signed/verified: an all-unsigned repo still refuses."""
    _, signers_dir, _, _ = two_ref_origin
    work = tmp_path / "unsigned"
    work.mkdir()
    _run("git", "init", "-q", "-b", "main", cwd=work)
    _run("git", "config", "user.email", "t@example.invalid", cwd=work)
    _run("git", "config", "user.name", "T", cwd=work)
    (work / "f").write_text("1\n", encoding="utf-8")
    _run("git", "add", "f", cwd=work)
    _run("git", "commit", "-qm", "one", cwd=work)
    _run("git", "-c", "tag.gpgSign=false", "tag", "-a", "v1.0.0", "-m", "v1.0.0", cwd=work)
    origin = tmp_path / "unsigned.git"
    _run("git", "clone", "--bare", "-q", str(work), str(origin))
    with pytest.raises(ValueError, match=r"no v\* tag verifies"):
        nuk.sync_source(_src(origin), signers_dir, tmp_path / "state")


def test_prepare_source_archives_the_tag_tree_and_the_branch_tree(two_ref_origin, tmp_path):
    """Task 10: two trees are archived and both commits stored on the context."""
    origin, signers_dir, tag_sha, branch_sha = two_ref_origin
    block: dict = {}
    ctx = nuk._prepare_source(
        _src(origin, apply=("facilities",)),
        block,
        role="app",
        self_ip=None,
        signers_dir=signers_dir,
        state_dir=tmp_path / "state",
        scratch=tmp_path / "scratch",
        platform=None,
    )
    assert block["tag"] == "v1.0.0"
    assert block["commit"] == tag_sha
    assert ctx.trees["tag"] != ctx.trees["branch"]
    assert (ctx.trees["tag"] / "f").read_text(encoding="utf-8") == "1\n"
    assert (ctx.trees["branch"] / "f").read_text(encoding="utf-8") == "2\n"
    assert ctx.commits == {"tag": tag_sha, "branch": branch_sha}
