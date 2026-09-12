"""The convergence loop's trust boundary and mechanics (spec §7).

Real git repos with real SSH-signed tags in tmp_path — no mocks on the crypto,
because the crypto IS the security boundary (spec §7.3). No network, no docker,
no /opt/nuklaut.

HERMETICITY: every git invocation here runs with GIT_CONFIG_GLOBAL and
GIT_CONFIG_SYSTEM pointed at a nonexistent path. Without that, a developer whose
global config sets `tag.gpgsign = true` (this repo's own author does) silently
SIGNS the tags these tests create as unsigned, and every negative case passes for
the wrong reason.
"""

from __future__ import annotations

import subprocess

import nuk
import pytest


@pytest.fixture(autouse=True)
def _hermetic_git(tmp_path, monkeypatch):
    """Neutralize the developer's global/system git config for every test."""
    nowhere = str(tmp_path / "no-such-gitconfig")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", nowhere)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", nowhere)


def _run(*cmd, cwd=None):
    """Run a command, raising with captured output on failure."""
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def signer(tmp_path):
    """An ed25519 key plus an allowed-signers file naming it."""
    key = tmp_path / "signing"
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "signer", "-f", str(key))
    signers = tmp_path / "allowed_signers"
    signers.write_text(
        f"signer {key.with_suffix('.pub').read_text(encoding='utf-8').strip()}\n",
        encoding="utf-8",
    )
    return key.with_suffix(".pub"), signers


@pytest.fixture
def repo(tmp_path):
    """An initialized git repo with one commit."""
    r = tmp_path / "repo"
    r.mkdir()
    _run("git", "init", "-q", "-b", "main", cwd=r)
    _run("git", "config", "user.email", "t@example.invalid", cwd=r)
    _run("git", "config", "user.name", "T", cwd=r)
    (r / "f").write_text("1\n", encoding="utf-8")
    _run("git", "add", "f", cwd=r)
    _run("git", "commit", "-qm", "one", cwd=r)
    return r


def _commit(repo, text):
    """Add a commit and return its sha."""
    (repo / "f").write_text(text, encoding="utf-8")
    _run("git", "commit", "-qam", text, cwd=repo)
    return _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()


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


def _plain_tag(repo, tag):
    """Create an explicitly UNSIGNED annotated tag at HEAD."""
    _run("git", "-c", "tag.gpgSign=false", "tag", "-a", tag, "-m", tag, cwd=repo)


def test_a_signed_tag_verifies(repo, signer):
    pubkey, signers = signer
    _sign_tag(repo, pubkey, "v1.0.0")
    assert nuk.verify_tag(repo, signers, "v1.0.0") is True


def test_an_unsigned_tag_does_not_verify(repo, signer):
    _, signers = signer
    _plain_tag(repo, "v1.0.0")
    assert nuk.verify_tag(repo, signers, "v1.0.0") is False


def test_a_tag_signed_by_a_foreign_key_does_not_verify(repo, signer, tmp_path):
    """Signed, valid, and not by anyone we trust."""
    _, signers = signer
    other = tmp_path / "other"
    _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "other", "-f", str(other))
    _sign_tag(repo, other.with_suffix(".pub"), "v1.0.0")
    assert nuk.verify_tag(repo, signers, "v1.0.0") is False


def test_resolve_returns_none_when_nothing_verifies(repo, signer):
    _, signers = signer
    _plain_tag(repo, "v1.0.0")
    assert nuk.resolve_signed_tag(repo, signers) is None


def test_resolve_skips_an_unsigned_tag_rather_than_failing(repo, signer):
    """One unsigned tag from anyone with write access must not be a DoS."""
    pubkey, signers = signer
    _sign_tag(repo, pubkey, "v1.0.0")
    _commit(repo, "2")
    _plain_tag(repo, "v1.1.0")
    assert nuk.resolve_signed_tag(repo, signers) == "v1.0.0"


def test_resolve_prefers_the_topological_descendant_over_creatordate(repo, signer):
    """Regression: v2.0.1 shadowed v2.1.0 during host verification 2026-08-15.

    Both tags are created inside the same second, so `--sort=-creatordate` ties
    and for-each-ref breaks the tie on refname — where v2.1.0 sorts BELOW v2.0.1.
    Taking the first verifying hit would pin the loop to the older tag forever.
    """
    pubkey, signers = signer
    _sign_tag(repo, pubkey, "v2.0.1")
    _commit(repo, "2")
    _sign_tag(repo, pubkey, "v2.1.0")
    assert nuk.resolve_signed_tag(repo, signers) == "v2.1.0"


def test_downgrade_guard_passes_for_a_descendant(repo, signer, tmp_path):
    pubkey, _ = signer
    first = _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    state = tmp_path / "last-applied-tag"
    nuk.record_applied("v1.0.0", first, state)
    _commit(repo, "2")
    _sign_tag(repo, pubkey, "v1.1.0")
    nuk.assert_not_downgrade(repo, "v1.1.0", state)  # must not raise


def test_downgrade_guard_refuses_a_walk_backwards(repo, signer, tmp_path):
    """The attack IS tag deletion, so the guard compares SHAs, never tag names."""
    pubkey, _ = signer
    _sign_tag(repo, pubkey, "v1.0.0")
    newer = _commit(repo, "2")
    _sign_tag(repo, pubkey, "v1.1.0")
    state = tmp_path / "last-applied-tag"
    nuk.record_applied("v1.1.0", newer, state)
    _run("git", "tag", "-d", "v1.1.0", cwd=repo)  # the deletion
    with pytest.raises(ValueError, match="not a descendant"):
        nuk.assert_not_downgrade(repo, "v1.0.0", state)


def test_downgrade_guard_refuses_an_unknown_previous_commit(repo, tmp_path):
    """Rewritten history is indistinguishable from an attack — refuse."""
    state = tmp_path / "last-applied-tag"
    nuk.record_applied("v9.9.9", "f" * 40, state)
    with pytest.raises(ValueError, match="unknown to this repo"):
        nuk.assert_not_downgrade(repo, "HEAD", state)


def test_downgrade_guard_is_a_no_op_on_first_run(repo, tmp_path):
    nuk.assert_not_downgrade(repo, "HEAD", tmp_path / "never-written")


def test_record_applied_writes_tag_and_sha(tmp_path):
    state = tmp_path / "nested" / "last-applied-tag"
    nuk.record_applied("v1.0.0", "a" * 40, state)
    assert state.read_text(encoding="utf-8") == f"v1.0.0 {'a' * 40}\n"


# --- the loop: lock, fetch, verify, archive ------------------------------------


ORG_FILE = "nuklaut.astrocloud.org.yml"


@pytest.fixture
def loop(repo, signer, tmp_path, monkeypatch):
    """A signed repo plus a state dir, with apply/render/reap stubbed out.

    The repo carries an org manifest at ORG_FILE because the edge refuses to
    converge without one (Task 6). Its CONTENT is irrelevant here — the tests
    that reach rendering stub `load_org` — but its PRESENCE is what the edge
    checks, so it has to be in the archived tree.
    """
    pubkey, signers = signer
    (repo / ORG_FILE).write_text("apiVersion: nukorg/v1\n", encoding="utf-8")
    _run("git", "add", ORG_FILE, cwd=repo)
    _run("git", "commit", "-qm", "org", cwd=repo)
    _sign_tag(repo, pubkey, "v1.0.0")
    # Set up a local origin remote so fetch doesn't fail
    origin = tmp_path / "origin"
    _run("git", "clone", "--bare", str(repo), str(origin))
    _run("git", "remote", "add", "origin", str(origin), cwd=repo)
    _run("git", "push", "origin", "main", "--tags", cwd=repo)
    state = tmp_path / "state"
    monkeypatch.setattr(nuk, "apply_tree", lambda tree, role: [])
    monkeypatch.setattr(nuk, "reap_report", lambda tree: [])
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    return repo, signers, state


def test_converge_refuses_without_a_trust_anchor(loop, tmp_path, capsys):
    repo, _, state = loop
    code = nuk.cmd_converge(
        repo=repo, signers=tmp_path / "absent", state_dir=state, org_file=ORG_FILE
    )
    assert code == 1
    assert "trust anchor" in capsys.readouterr().err


def test_converge_refuses_when_no_tag_verifies(repo, signer, tmp_path, capsys, monkeypatch):
    _, signers = signer
    origin = tmp_path / "origin"
    _run("git", "clone", "--bare", str(repo), str(origin))
    _run("git", "remote", "add", "origin", str(origin), cwd=repo)
    _plain_tag(repo, "v1.0.0")
    monkeypatch.setattr(nuk, "apply_tree", lambda tree, role: pytest.fail("must not apply"))
    code = nuk.cmd_converge(
        repo=repo, signers=signers, state_dir=tmp_path / "state", org_file=ORG_FILE
    )
    assert code == 1
    assert "no v* tag verifies" in capsys.readouterr().err


def test_converge_refuses_a_downgrade(repo, signer, tmp_path, monkeypatch, capsys):
    pubkey, signers = signer
    origin = tmp_path / "origin"
    _run("git", "clone", "--bare", str(repo), str(origin))
    _run("git", "remote", "add", "origin", str(origin), cwd=repo)
    _sign_tag(repo, pubkey, "v1.0.0")
    newer = _commit(repo, "2")
    _sign_tag(repo, pubkey, "v1.1.0")
    _run("git", "push", "origin", "main", "--tags", cwd=repo)
    state = tmp_path / "state"
    state.mkdir()
    nuk.record_applied("v1.1.0", newer, state / "last-applied-tag")
    # Delete v1.1.0 from the origin (simulating the attack)
    _run("git", "-C", str(origin), "tag", "-d", "v1.1.0")
    _run("git", "tag", "-d", "v1.1.0", cwd=repo)
    monkeypatch.setattr(nuk, "apply_tree", lambda tree, role: pytest.fail("must not apply"))
    code = nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE)
    assert code == 1
    assert "not a descendant" in capsys.readouterr().err
    # Spec §12, "loop — signature": prior state UNTOUCHED. A refusal that quietly
    # rewrote last-applied-tag would let the very next cycle accept the downgrade.
    assert (state / "last-applied-tag").read_text(encoding="utf-8").split()[0] == "v1.1.0"


def test_converge_records_the_applied_tag(loop, capsys):
    repo, signers, state = loop
    assert nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE) == 0
    recorded = (state / "last-applied-tag").read_text(encoding="utf-8").split()
    assert recorded[0] == "v1.0.0"
    assert recorded[1] == _run("git", "rev-parse", "v1.0.0^{commit}", cwd=repo).stdout.strip()


def test_converge_exits_zero_and_applies_nothing_while_the_lock_is_held(loop, monkeypatch):
    """Spec §7.5: a skipped cycle is harmless; the next poke or floor picks it up.

    A blocking wait would instead pile up systemd jobs.
    """
    repo, signers, state = loop
    monkeypatch.setattr(nuk, "apply_tree", lambda tree, role: pytest.fail("must not apply"))
    with nuk.converge_lock(state) as acquired:
        assert acquired is True
        code = nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE)
    assert code == 0
    assert not (state / "last-applied-tag").exists()


def test_archive_tree_extracts_the_commit_not_the_worktree(repo, tmp_path):
    """Spec §7 step 4: never the live worktree, which can carry uncommitted edits."""
    commit = _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    (repo / "f").write_text("UNCOMMITTED\n", encoding="utf-8")
    (repo / "untracked").write_text("junk\n", encoding="utf-8")
    dest = tmp_path / "scratch"
    nuk.archive_tree(repo, commit, dest)
    assert (dest / "f").read_text(encoding="utf-8") == "1\n"
    assert not (dest / "untracked").exists()


def test_converge_applies_a_new_tag_restoring_an_old_tree(loop, signer, monkeypatch):
    """Spec §12, 'loop — monotonic (§7.3a)': fleet rollback applies cleanly.

    The guard is ancestry-based (Task 3), so 'a new tag on an old tree' means a
    NEW commit whose tree restores the old one — a revert commit. Tagging the
    OLD commit directly is refused by design; this test pins down the intended
    forward-only shape.
    """
    repo, signers, state = loop
    pubkey, _ = signer
    # v1.0.0 already exists (the loop fixture signed it); append a release on top.
    _commit(repo, "2")
    _sign_tag(repo, pubkey, "v1.1.0")  # file "2" — recorded as applied
    nuk.record_applied(
        "v1.1.0",
        _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip(),
        state / "last-applied-tag",
    )
    _run("git", "revert", "--no-edit", "HEAD", cwd=repo)  # file "1" again
    _sign_tag(repo, pubkey, "v1.2.0")  # the rollback tag
    _run("git", "push", "origin", "main", "--tags", cwd=repo)
    applied = []

    def mock_apply_tree(tree, role):
        applied.append((tree / "f").read_text())
        return []

    monkeypatch.setattr(nuk, "apply_tree", mock_apply_tree)
    monkeypatch.setattr(nuk, "reap_report", lambda tree: [])
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    code = nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE)
    assert code == 0
    assert applied == ["1\n"]
    assert (state / "last-applied-tag").read_text(encoding="utf-8").split()[0] == "v1.2.0"


def test_converge_refuses_a_new_tag_on_the_old_commit_itself(loop, signer, monkeypatch, capsys):
    """§7.3a strengthening: 'old commit, new tag' is the deletion attack's shape.

    The attack deletes the applied tag, then tags the OLD commit with a NEW
    signed tag — which verifies and is creatordate-newest, so the resolver picks
    it. The ancestry guard is the only thing standing between that and a silent
    walk backwards, and it must refuse with the prior state untouched.
    """
    repo, signers, state = loop
    pubkey, _ = signer
    origin = _run("git", "config", "remote.origin.url", cwd=repo).stdout.strip()
    old_sha = _run("git", "rev-parse", "v1.0.0^{commit}", cwd=repo).stdout.strip()
    _commit(repo, "2")
    _sign_tag(repo, pubkey, "v1.1.0")
    _run("git", "push", "origin", "main", "--tags", cwd=repo)
    nuk.record_applied(
        "v1.1.0",
        _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip(),
        state / "last-applied-tag",
    )
    # Delete v1.1.0 from the origin (simulating the attack)
    _run("git", "-C", origin, "tag", "-d", "v1.1.0")
    _run("git", "tag", "-d", "v1.1.0", cwd=repo)
    _run(
        "git",
        "-c",
        "gpg.format=ssh",
        "-c",
        f"user.signingkey={pubkey}",
        "tag",
        "-s",
        "v1.2.0",
        "-m",
        "v1.2.0",
        old_sha,
        cwd=repo,
    )
    _run("git", "push", "origin", "--tags", cwd=repo)
    monkeypatch.setattr(nuk, "apply_tree", lambda tree, role: pytest.fail("must not apply"))
    code = nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE)
    assert code == 1
    assert "not a descendant" in capsys.readouterr().err
    assert (state / "last-applied-tag").read_text(encoding="utf-8").split()[0] == "v1.1.0"


# --- apply order and isolation --------------------------------------------------

FACILITY_YML = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: data-stack}
spec:
  placement: {role: data}
"""

DEPLOYMENT_YML = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: hello}
spec:
  placement: {role: app}
  source: {repo: "git@github.com:astrojones/hello.git"}
"""

# A facility that declares an env capability, and a Deployment that consumes it
# through the §5.3 static map (spec.databases -> env capability "databases").
DATA_FACILITY_YML = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: data-stack}
spec:
  placement: {role: app}
  provides:
    env: {capability: databases, bind: postgres}
"""

DB_APP_YML = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: hello}
spec:
  placement: {role: app}
  source: {repo: "git@github.com:astrojones/hello.git"}
  databases: {postgres: true}
"""


def _tree(tmp_path, **files):
    """Build a manifest tree under `tmp_path` from facilities=/deployments= YAML bodies."""
    root = tmp_path / "tree"
    root.mkdir(parents=True, exist_ok=True)
    for directory, docs in files.items():
        d = root / directory
        d.mkdir(parents=True, exist_ok=True)
        for name, body in docs.items():
            (d / f"{name}.yml").write_text(body, encoding="utf-8")
    return root


def test_apply_tree_applies_facilities_before_deployments(tmp_path, monkeypatch):
    """Spec §7.1 — only facility HEALTH needs ordering, and that is same-host."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": FACILITY_YML.replace("role: data", "role: app")},
        deployments={"hello": DEPLOYMENT_YML},
    )
    order = []
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp: order.append(path.stem))
    results = nuk.apply_tree(tree, "app")
    assert order == ["data-stack", "hello"]
    assert [r["result"] for r in results] == ["ok", "ok"]
    assert [r["kind"] for r in results] == ["Facility", "Deployment"]


def test_apply_tree_skips_manifests_placed_on_another_host(tmp_path, monkeypatch):
    """Spec §5.4 — placement.role != this host is a clean no-op, nothing applied."""
    tree = _tree(
        tmp_path, facilities={"data-stack": FACILITY_YML}, deployments={"hello": DEPLOYMENT_YML}
    )
    applied = []
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp: applied.append(path.stem))
    results = nuk.apply_tree(tree, "app")
    assert applied == ["hello"]
    assert len(results) == 1


def test_one_failing_deployment_does_not_stop_the_rest(tmp_path, monkeypatch):
    """Spec §7.5 — log, continue, per-manifest result in status."""
    second = DEPLOYMENT_YML.replace("name: hello", "name: zulu")
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML, "zulu": second})

    def flaky(path, _rp):
        if path.stem == "hello":
            msg = "hello: image pull failed"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    results = nuk.apply_tree(tree, "app")
    assert [(r["name"], r["result"]) for r in results] == [("hello", "failed"), ("zulu", "ok")]
    assert "image pull failed" in results[0]["error"]


def test_a_malformed_manifest_is_recorded_not_raised(tmp_path, monkeypatch):
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML, "broken": "kind: Nonsense\n"})
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp: None)
    results = nuk.apply_tree(tree, "app")
    by_name = {r["name"]: r for r in results}
    assert by_name["broken.yml"]["result"] == "failed"
    assert by_name["hello"]["result"] == "ok"


def test_apply_tree_tolerates_a_tree_with_neither_directory(tmp_path):
    assert nuk.apply_tree(tmp_path / "empty", "app") == []


def test_a_deployment_consuming_a_failed_facility_is_refused(tmp_path, monkeypatch):
    """Spec §7.5: facility fails health -> Deployments consuming it refuse.

    `consumes` is the REAL function — the static map (§5.3) is part of the
    assertion, not the harness.
    """
    tree = _tree(
        tmp_path,
        facilities={"data-stack": DATA_FACILITY_YML},
        deployments={"hello": DB_APP_YML},
    )

    def flaky(path, _rp):
        if path.stem == "data-stack":
            msg = "data-stack: container 'nuk-postgres' is not healthy"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    results = nuk.apply_tree(tree, "app")
    by_name = {r["name"]: r for r in results}
    assert by_name["data-stack"]["result"] == "failed"
    assert by_name["hello"]["result"] == "refused"
    assert "databases" in by_name["hello"]["error"]


def test_a_deployment_consuming_nothing_applies_despite_a_failed_facility(tmp_path, monkeypatch):
    """A Deployment that consumes nothing is not coupled to any facility (§5.3)."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": DATA_FACILITY_YML},
        deployments={"hello": DEPLOYMENT_YML},
    )

    def flaky(path, _rp):
        if path.stem == "data-stack":
            msg = "data-stack: not healthy"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    results = nuk.apply_tree(tree, "app")
    by_name = {r["name"]: r for r in results}
    assert by_name["hello"]["result"] == "ok"


def test_a_facility_placed_on_another_host_does_not_poison(tmp_path, monkeypatch):
    """Cross-host facility health is unknown (§13) — only same-host failures refuse."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": DATA_FACILITY_YML.replace("role: app", "role: data")},
        deployments={"hello": DB_APP_YML},
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp: None)
    results = nuk.apply_tree(tree, "app")
    assert [r["name"] for r in results] == ["hello"]
    assert results[0]["result"] == "ok"


# --- reap, render, status -------------------------------------------------------


def test_reap_reports_orphans_and_deletes_nothing(tmp_path, monkeypatch):
    """Spec §7.4 — the loop never removes deployments."""
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML})
    deploys = tmp_path / "deployments"
    for name in ("hello", "app-alpha", "oauth"):
        (deploys / name).mkdir(parents=True)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    assert nuk.reap_report(tree) == ["app-alpha", "oauth"]
    assert (deploys / "app-alpha").is_dir()
    assert (deploys / "oauth").is_dir()


def test_reap_counts_facilities_as_declared(tmp_path, monkeypatch):
    """A facility deployed here is not an orphan just because it is not a Deployment."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": FACILITY_YML},
        deployments={"hello": DEPLOYMENT_YML},
    )
    deploys = tmp_path / "deployments"
    for name in ("hello", "data-stack"):
        (deploys / name).mkdir(parents=True)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    assert nuk.reap_report(tree) == []


def test_reap_is_empty_when_nothing_is_deployed(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "absent")
    assert nuk.reap_report(tmp_path / "tree") == []


def test_status_file_records_the_cycle(tmp_path):
    path = tmp_path / "converge-status.json"
    nuk.write_converge_status(
        path,
        tag="v1.2.0",
        commit="a" * 40,
        role="app",
        results=[{"name": "hello", "kind": "Deployment", "result": "ok", "error": None}],
        rendered=[],
        warnings=["oauth"],
    )
    data = nuk.read_converge_status(path)
    assert data["tag"] == "v1.2.0"
    assert data["role"] == "app"
    assert data["manifests"][0]["name"] == "hello"
    assert data["reapWarnings"] == ["oauth"]
    assert data["appliedAt"].endswith("Z")


def test_read_status_is_none_when_absent(tmp_path):
    assert nuk.read_converge_status(tmp_path / "absent.json") is None


def test_converge_writes_a_status_file(loop, monkeypatch):
    repo, signers, state = loop
    monkeypatch.setattr(
        nuk,
        "apply_tree",
        lambda tree, role: [{"name": "hello", "kind": "Deployment", "result": "ok", "error": None}],
    )
    monkeypatch.setattr(nuk, "reap_report", lambda tree: ["oauth"])
    assert nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE) == 0
    data = nuk.read_converge_status(state / "converge-status.json")
    assert data["tag"] == "v1.0.0"
    assert data["reapWarnings"] == ["oauth"]


def test_converge_warns_about_orphans_on_stdout(loop, monkeypatch, capsys):
    repo, signers, state = loop
    monkeypatch.setattr(nuk, "reap_report", lambda tree: ["hello", "oauth"])
    nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE)
    out = capsys.readouterr().out
    assert "WARN: 2 deployed app(s) not present at v1.0.0" in out
    assert "nuk delete" in out


def test_a_non_edge_host_renders_no_routers(loop, monkeypatch):
    repo, signers, state = loop
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(
        nuk, "render_edge_routers", lambda tree, org: pytest.fail("only the edge renders")
    )
    assert nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE) == 0


def test_the_edge_renders_every_router(loop, monkeypatch):
    repo, signers, state = loop
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "load_org", lambda path: "ORG")
    monkeypatch.setattr(nuk, "render_edge_routers", lambda tree, org: ["hello", "app-alpha"])
    assert nuk.cmd_converge(repo=repo, signers=signers, state_dir=state, org_file=ORG_FILE) == 0
    assert nuk.read_converge_status(state / "converge-status.json")["rendered"] == [
        "hello",
        "app-alpha",
    ]


def test_the_edge_refuses_when_the_org_manifest_is_missing(loop, monkeypatch, capsys):
    """Rendering resolves every backend IP from it; guessing is not an option."""
    repo, signers, state = loop
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    code = nuk.cmd_converge(
        repo=repo, signers=signers, state_dir=state, org_file="nuklaut.absent.org.yml"
    )
    assert code == 1
    assert "org manifest" in capsys.readouterr().err
