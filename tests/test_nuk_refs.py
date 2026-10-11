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


def _signed_work(tmp_path, name="astrojones"):
    """A work repo on `main` plus its signing key and `allowed_signers.d` entry.

    Returns `(work, pubkey, signers_dir)`; callers commit, `_sign_tag`, then clone bare.
    """
    key = tmp_path / "signing"
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key))
    pubkey = key.with_suffix(".pub")
    signers_dir = tmp_path / "allowed_signers.d"
    signers_dir.mkdir()
    (signers_dir / name).write_text(
        f"{name} {pubkey.read_text(encoding='utf-8').strip()}\n", encoding="utf-8"
    )
    work = tmp_path / "work"
    work.mkdir()
    _run("git", "init", "-q", "-b", "main", cwd=work)
    _run("git", "config", "user.email", "t@example.invalid", cwd=work)
    _run("git", "config", "user.name", "T", cwd=work)
    (work / "f").write_text("1\n", encoding="utf-8")
    _run("git", "add", "f", cwd=work)
    _run("git", "commit", "-qm", "one", cwd=work)
    return work, pubkey, signers_dir


def _rev(work, ref="HEAD"):
    return _run("git", "rev-parse", ref, cwd=work).stdout.strip()


def test_sync_source_still_refuses_a_signed_tag_downgrade(tmp_path):
    """Task 12 regression: branch mode must not weaken the signed-tag downgrade guard.

    Apply `v1.1.0`, then delete it upstream. The newest verifying tag falls back to
    `v1.0.0`, an ancestor — the guard must refuse exactly as it did before Task 10.
    """
    work, pubkey, signers_dir = _signed_work(tmp_path)
    _sign_tag(work, pubkey, "v1.0.0")
    (work / "f").write_text("2\n", encoding="utf-8")
    _run("git", "commit", "-qam", "two", cwd=work)
    _sign_tag(work, pubkey, "v1.1.0")
    origin = tmp_path / "origin.git"
    _run("git", "clone", "--bare", "-q", str(work), str(origin))

    state = tmp_path / "state"
    tag, commit, _branch = nuk.sync_source(_src(origin), signers_dir, state)
    assert tag == "v1.1.0"
    nuk.record_applied(tag, commit, nuk.source_state_dir(state, "astrojones") / "last-applied-tag")
    _run("git", "-C", str(origin), "tag", "-d", "v1.1.0")
    with pytest.raises(ValueError, match="not a descendant"):
        nuk.sync_source(_src(origin), signers_dir, state)


def test_sync_source_exempts_an_older_unsigned_branch_head(tmp_path):
    """Task 12: the branch head is not downgrade-guarded — an older head is legitimate.

    `main` advances to the branch head. The newest signed tag `v2.0.0` is cut on a side
    branch, so it is NOT an ancestor of the branch head. A prior cycle applied `v2.0.0`;
    the guard must compare the tag only and never refuse over the branch head.
    """
    work, pubkey, signers_dir = _signed_work(tmp_path)
    _sign_tag(work, pubkey, "v1.0.0")
    c1 = _rev(work)
    (work / "f").write_text("2\n", encoding="utf-8")
    _run("git", "commit", "-qam", "two", cwd=work)
    branch_sha = _rev(work)
    _run("git", "checkout", "-qb", "release", c1, cwd=work)
    (work / "f").write_text("3\n", encoding="utf-8")
    _run("git", "commit", "-qam", "three", cwd=work)
    _sign_tag(work, pubkey, "v2.0.0")
    tag_sha = _rev(work)
    _run("git", "checkout", "-q", "main", cwd=work)
    origin = tmp_path / "origin.git"
    _run("git", "clone", "--bare", "-q", str(work), str(origin))

    state = tmp_path / "state"
    sdir = nuk.source_state_dir(state, "astrojones")
    sdir.mkdir(parents=True)
    nuk.record_applied("v2.0.0", tag_sha, sdir / "last-applied-tag")

    tag, got_tag_sha, got_branch_sha = nuk.sync_source(_src(origin), signers_dir, state)
    assert tag == "v2.0.0"
    assert got_tag_sha == tag_sha
    assert got_branch_sha == branch_sha


def test_sync_source_refuses_a_source_whose_remote_has_no_main_branch(tmp_path):
    """I1: a remote whose default branch is not `main` fails the WHOLE fetch.

    `SOURCE_BRANCH` is hardcoded to `main` and shares ONE fetch with the signed
    tags, so its valid signed tag can never deploy. Refuse with the actual reason
    instead of a bare `git fetch failed`. (Per-source/per-deployment branches are
    a future follow-up; this only names the cause.)
    """
    work, pubkey, signers_dir = _signed_work(tmp_path)
    _run("git", "branch", "-m", "master", cwd=work)  # rename the only branch
    _sign_tag(work, pubkey, "v1.0.0")
    origin = tmp_path / "origin.git"
    _run("git", "clone", "--bare", "-q", str(work), str(origin))

    with pytest.raises(ValueError, match="no main branch"):
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


def _ref_tree(root, marker: str) -> None:
    """One deployment tree at `root`: a signed `prod` and an unsigned `test`.

    The two trees differ only by `marker`, so reading an applied manifest's
    `spec.compose.file` proves which tree it came from.
    """
    d = root / "deployments"
    d.mkdir(parents=True)
    (d / "prod.yml").write_text(
        "apiVersion: nuk/v1\n"
        "kind: Deployment\n"
        "metadata: {name: prod}\n"
        f"spec: {{source: {{repo: 'r'}}, compose: {marker}.yml}}\n",
        encoding="utf-8",
    )
    (d / "test.yml").write_text(
        "apiVersion: nuk/v1\n"
        "kind: Deployment\n"
        "metadata: {name: test}\n"
        f"spec: {{source: {{repo: 'r', unsigned: true}}, compose: {marker}.yml}}\n",
        encoding="utf-8",
    )


TAG_SHA = "a" * 40
BRANCH_SHA = "b" * 40


def _tree_and_branch(tmp_path, commits: dict) -> nuk.TreeContext:
    tag, branch = tmp_path / "tag", tmp_path / "branch"
    _ref_tree(tag, "tag")
    _ref_tree(branch, "branch")
    return nuk.TreeContext.build(
        tag,
        "app",
        None,
        None,
        nuk.APPLY_ALL,
        trees={"tag": tag, "branch": branch},
        commits=commits,
    )


def test_apply_tree_selects_the_tree_per_deployment(tmp_path, monkeypatch):
    """Task 11: `spec.source.unsigned` picks the branch tree, everything else the tag tree."""
    ctx = _tree_and_branch(tmp_path, {"tag": TAG_SHA, "branch": BRANCH_SHA})
    calls: dict[str, dict] = {}

    def fake(path, _rp, **k):
        calls[path.name] = {
            "text": path.read_text(encoding="utf-8"),
            "pin_commit": k.get("pin_commit"),
        }

    monkeypatch.setattr(nuk, "cmd_apply", fake)
    nuk.apply_tree(ctx)

    assert "compose: branch.yml" in calls["test.yml"]["text"]  # unsigned -> branch tree
    assert "compose: tag.yml" in calls["prod.yml"]["text"]  # signed -> tag tree, never branch
    # The tree choice must reach the BUILD, not just the manifest read: a signed
    # deployment pins the clone to the tag commit; an unsigned one follows the head.
    assert calls["prod.yml"]["pin_commit"] == TAG_SHA
    assert calls["test.yml"]["pin_commit"] is None


def test_apply_tree_without_recorded_commits_does_not_pin(tmp_path, monkeypatch):
    """A hand-run/Task-10 context carries no `commits`: degrade to today's behaviour (no pin)."""
    ctx = _tree_and_branch(tmp_path, {})
    seen: dict[str, dict] = {}

    def fake(path, _rp, **k):
        seen[path.name] = {"pin_commit": k.get("pin_commit")}

    monkeypatch.setattr(nuk, "cmd_apply", fake)
    nuk.apply_tree(ctx)  # must not raise on the missing "tag" key

    assert seen["prod.yml"]["pin_commit"] is None
    assert seen["test.yml"]["pin_commit"] is None
