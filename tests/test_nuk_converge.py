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

import shlex
import subprocess
from pathlib import Path

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


# --- archive ---------------------------------------------------------------------


def _ctx(tree, role):
    return nuk.TreeContext.build(tree, role, None, None, nuk.APPLY_ALL)


def test_archive_tree_extracts_the_commit_not_the_worktree(repo, tmp_path):
    """Spec §7 step 4: never the live worktree, which can carry uncommitted edits."""
    commit = _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    (repo / "f").write_text("UNCOMMITTED\n", encoding="utf-8")
    (repo / "untracked").write_text("junk\n", encoding="utf-8")
    dest = tmp_path / "scratch"
    nuk.archive_tree(repo, commit, dest)
    assert (dest / "f").read_text(encoding="utf-8") == "1\n"
    assert not (dest / "untracked").exists()


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

# Two `app` hosts: a Deployment placed `{role: app}` with no `host` names neither,
# so placement_matches cannot decide and must surface a loud failure (§13).
TWO_APP_HOSTS_ORG_YML = """\
apiVersion: nukorg/v1
kind: Org
metadata: {name: astrojones}
domains: [jonaheidsick.de]
platformDomain: jonaheidsick.de
acmeEmail: admin@jonaheidsick.de
hosts:
  - {name: ingress, provider: incus, metal: metal, role: edge, privateIp: 10.0.10.241}
  - {name: metal, provider: manual, ip: 1.2.3.4, role: hypervisor, privateIp: 10.0.2.2}
  - {name: deploy, provider: incus, metal: metal, role: app, privateIp: 10.0.10.107}
  - {name: kolbe-app, provider: incus, metal: metal, role: app, privateIp: 10.0.10.190}
facilities: {dns: wildcard, tls: dns01, dnsProvider: hetzner, secrets: sops, runners: ephemeral}
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
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: order.append(path.stem))
    results = nuk.apply_tree(_ctx(tree, "app"))
    assert order == ["data-stack", "hello"]
    assert [r.result for r in results] == ["ok", "ok"]
    assert [r.kind for r in results] == ["Facility", "Deployment"]


def test_apply_tree_skips_manifests_placed_on_another_host(tmp_path, monkeypatch):
    """Spec §5.4 — placement.role != this host is a clean no-op, nothing applied."""
    tree = _tree(
        tmp_path, facilities={"data-stack": FACILITY_YML}, deployments={"hello": DEPLOYMENT_YML}
    )
    applied = []
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: applied.append(path.stem))
    results = nuk.apply_tree(_ctx(tree, "app"))
    assert applied == ["hello"]
    assert len(results) == 1


def test_ambiguous_app_deployment_fails_not_silently_skips(tmp_path, monkeypatch):
    # An org with two app hosts and a deployment pinned to neither must surface a
    # FAILED result for that deployment, never an "ok" on both hosts.
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML})
    (tree / nuk.DEFAULT_ORG_FILE).write_text(TWO_APP_HOSTS_ORG_YML, encoding="utf-8")
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: None)
    results = nuk.apply_tree(_ctx(tree, "app"))
    entry = next(r for r in results if r.name == "hello")
    assert entry.result == "failed"
    assert "ambiguous" in entry.error


def test_one_failing_deployment_does_not_stop_the_rest(tmp_path, monkeypatch):
    """Spec §7.5 — log, continue, per-manifest result in status."""
    second = DEPLOYMENT_YML.replace("name: hello", "name: zulu")
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML, "zulu": second})

    def flaky(path, _rp, **_k):
        if path.stem == "hello":
            msg = "hello: image pull failed"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    results = nuk.apply_tree(_ctx(tree, "app"))
    assert [(r.name, r.result) for r in results] == [("hello", "failed"), ("zulu", "ok")]
    assert "image pull failed" in results[0].error


def test_a_malformed_manifest_is_recorded_not_raised(tmp_path, monkeypatch):
    tree = _tree(tmp_path, deployments={"hello": DEPLOYMENT_YML, "broken": "kind: Nonsense\n"})
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: None)
    results = nuk.apply_tree(_ctx(tree, "app"))
    by_name = {r.name: r for r in results}
    assert by_name["broken.yml"].result == "failed"
    assert by_name["hello"].result == "ok"


def test_apply_tree_tolerates_a_tree_with_neither_directory(tmp_path):
    assert nuk.apply_tree(_ctx(tmp_path / "empty", "app")) == []


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

    def flaky(path, _rp, **_k):
        if path.stem == "data-stack":
            msg = "data-stack: container 'nuk-postgres' is not healthy"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    monkeypatch.setattr(nuk, "SECRETS", tmp_path / "secrets")  # db env files land here
    results = nuk.apply_tree(_ctx(tree, "app"))
    by_name = {r.name: r for r in results}
    assert by_name["data-stack"].result == "failed"
    assert by_name["hello"].result == "refused"
    assert "databases" in by_name["hello"].error


def test_a_deployment_consuming_nothing_applies_despite_a_failed_facility(tmp_path, monkeypatch):
    """A Deployment that consumes nothing is not coupled to any facility (§5.3)."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": DATA_FACILITY_YML},
        deployments={"hello": DEPLOYMENT_YML},
    )

    def flaky(path, _rp, **_k):
        if path.stem == "data-stack":
            msg = "data-stack: not healthy"
            raise SystemExit(msg)

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    results = nuk.apply_tree(_ctx(tree, "app"))
    by_name = {r.name: r for r in results}
    assert by_name["hello"].result == "ok"


def test_a_facility_placed_on_another_host_does_not_poison(tmp_path, monkeypatch):
    """Cross-host facility health is unknown (§13) — only same-host failures refuse."""
    tree = _tree(
        tmp_path,
        facilities={"data-stack": DATA_FACILITY_YML.replace("role: app", "role: data")},
        deployments={"hello": DB_APP_YML},
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: None)
    results = nuk.apply_tree(_ctx(tree, "app"))
    assert [r.name for r in results] == ["hello"]
    assert results[0].result == "ok"


# --- reap -----------------------------------------------------------------------


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


# --- sources.yml and per-source sync (contracts C3) ---------------------------------

SOURCES_YML = """\
sources:
  - name: astrojones
    repo: git@github.com:astrojones/infra.git
    deploy_key: /etc/nuklaut/keys/astrojones
    apply: [routes]
  - name: bartixcloud
    repo: git@github.com:bartixcloud/infra.git
    deploy_key: /etc/nuklaut/keys/bartixcloud
    apply: [facilities, routes]
"""


def _sources(tmp_path, body):
    p = tmp_path / "sources.yml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_sources_orders_the_platform_first(tmp_path):
    sources = nuk.load_sources(_sources(tmp_path, SOURCES_YML))
    assert [s.name for s in sources.ordered()] == ["bartixcloud", "astrojones"]
    assert sources.ordered()[0].is_platform is True


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("apply: [routes]", "apply: [facilities]", "exactly one source"),
        ("apply: [facilities, routes]", "apply: [routes]", "exactly one source"),
        ("name: astrojones", "name: bartixcloud", "must be unique"),
        ("apply: [routes]", "apply: [roles]", "apply"),
        ("apply: [facilities, routes]", "apply: [facilities, databases]", "cannot apply"),
        ("deploy_key: /etc/nuklaut/keys/astrojones", "deploy_key: /k\n    rogue: 1", "rogue"),
    ],
)
def test_load_sources_refuses(tmp_path, old, new, match):
    with pytest.raises(ValueError, match=match):
        nuk.load_sources(_sources(tmp_path, SOURCES_YML.replace(old, new, 1)))


def test_load_sources_refuses_a_missing_file(tmp_path):
    with pytest.raises(ValueError, match=r"absent\.yml"):
        nuk.load_sources(tmp_path / "absent.yml")


def test_git_ssh_command_pins_the_deploy_key_and_the_host_key():
    argv = shlex.split(nuk.git_ssh_command(Path("/k/with space")))
    assert argv[:3] == ["ssh", "-i", "/k/with space"]
    assert "IdentitiesOnly=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert f"UserKnownHostsFile={nuk.KNOWN_HOSTS}" in argv
    assert "BatchMode=yes" in argv


@pytest.fixture
def principals(tmp_path):
    """Two signing keys (astrojones, kolbeapp-de) and a signers dir with one file per source."""
    keys = {}
    signers_dir = tmp_path / "allowed_signers.d"
    signers_dir.mkdir()
    for name in ("astrojones", "kolbeapp-de"):
        key = tmp_path / f"key-{name}"
        _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key))
        keys[name] = key.with_suffix(".pub")
        (signers_dir / name).write_text(
            f"{name} {keys[name].read_text(encoding='utf-8').strip()}\n", encoding="utf-8"
        )
    return keys, signers_dir


@pytest.fixture
def tenant_origin(repo, principals, tmp_path):
    keys, signers_dir = principals
    _sign_tag(repo, keys["astrojones"], "v1.0.0")
    origin = tmp_path / "origin.git"
    _run("git", "clone", "--bare", "-q", str(repo), str(origin))
    return repo, origin, keys, signers_dir


def _src(origin, name="astrojones"):
    return nuk.SourceEntry(
        name=name, repo=str(origin), deploy_key="/nonexistent/key", apply=["deployments"]
    )


def test_sync_source_returns_the_verified_tag_and_commit(tenant_origin, tmp_path):
    repo, origin, _, signers_dir = tenant_origin
    tag, commit, _branch = nuk.sync_source(_src(origin), signers_dir, tmp_path / "state")
    assert tag == "v1.0.0"
    tip = _run("git", "rev-parse", "HEAD", cwd=repo).stdout.strip()
    assert commit == tip
    assert (tmp_path / "state" / "sources" / "astrojones" / "repo" / "HEAD").is_file()


def test_a_sources_signers_file_rejects_another_sources_key(tenant_origin, tmp_path):
    """Astrojones signed the tag; the kolbeapp-de source trusts only kolbeapp-de's key."""
    _, origin, _, signers_dir = tenant_origin
    with pytest.raises(ValueError, match=r"no v\* tag verifies"):
        nuk.sync_source(_src(origin, "kolbeapp-de"), signers_dir, tmp_path / "state")


def test_sync_source_refuses_when_the_sources_signers_file_is_absent(tenant_origin, tmp_path):
    _, origin, _, _ = tenant_origin
    with pytest.raises(ValueError, match=r"allowed_signers\.d/astrojones"):
        nuk.sync_source(_src(origin), tmp_path / "empty-signers-dir", tmp_path / "state")


def test_sync_source_refuses_a_downgrade(tenant_origin, tmp_path):
    repo, origin, keys, signers_dir = tenant_origin
    _commit(repo, "2")
    _sign_tag(repo, keys["astrojones"], "v1.1.0")
    _run("git", "push", "-q", str(origin), "main", "--tags", cwd=repo)
    state = tmp_path / "state"
    tag, commit, _branch = nuk.sync_source(_src(origin), signers_dir, state)
    assert tag == "v1.1.0"
    nuk.record_applied(tag, commit, nuk.source_state_dir(state, "astrojones") / "last-applied-tag")
    _run("git", "-C", str(origin), "tag", "-d", "v1.1.0")
    with pytest.raises(ValueError, match="not a descendant"):
        nuk.sync_source(_src(origin), signers_dir, state)


def test_sync_source_refuses_when_the_fetch_fails(tmp_path, principals):
    _, signers_dir = principals
    with pytest.raises(ValueError, match="git fetch failed"):
        nuk.sync_source(_src(tmp_path / "no-such-origin.git"), signers_dir, tmp_path / "state")


def test_sync_source_follows_a_changed_repo_url(tenant_origin, tmp_path):
    _, origin, _, signers_dir = tenant_origin
    state = tmp_path / "state"
    nuk.sync_source(_src(origin), signers_dir, state)
    moved = tmp_path / "moved.git"
    _run("git", "clone", "--bare", "-q", str(origin), str(moved))
    assert nuk.sync_source(_src(moved), signers_dir, state)[0] == "v1.0.0"
    bare = state / "sources" / "astrojones" / "repo"
    assert _run("git", "-C", str(bare), "remote", "get-url", "origin").stdout.strip() == str(moved)


def test_sync_source_fetches_with_the_deploy_key(tenant_origin, tmp_path, monkeypatch):
    _, origin, _, signers_dir = tenant_origin
    real = subprocess.run
    seen = []

    def spy(argv, **kw):
        if "fetch" in argv:
            seen.append((kw.get("env") or {}).get("GIT_SSH_COMMAND"))
        return real(argv, **kw)

    monkeypatch.setattr(nuk.subprocess, "run", spy)
    nuk.sync_source(_src(origin), signers_dir, tmp_path / "state")
    assert seen == [nuk.git_ssh_command(Path("/nonexistent/key"))]


# --- archive_tree: a tenant repo is untrusted input to a root process ---------------


def test_archive_tree_extracts_a_plain_tree(repo, tmp_path):
    out = tmp_path / "out"
    nuk.archive_tree(repo, "HEAD", out)
    assert (out / "f").read_text(encoding="utf-8") == "1\n"


def test_archive_tree_refuses_a_symlink_that_leaves_the_tree(repo, tmp_path):
    (repo / "escape").symlink_to("/etc/passwd")
    _run("git", "add", "escape", cwd=repo)
    _run("git", "commit", "-qm", "link", cwd=repo)
    with pytest.raises(ValueError, match="unsafe archive member"):
        nuk.archive_tree(repo, "HEAD", tmp_path / "out")
    assert not (tmp_path / "out" / "escape").exists()
