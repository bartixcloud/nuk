"""The multi-source convergence loop (contracts C3): platform first, per-source trust and state.

Real git repos with real SSH-signed tags in tmp_path — no mocks on the crypto. The docker
layer (`cmd_apply`) is stubbed; everything else, including route rendering, runs for real.

HERMETICITY: git runs with GIT_CONFIG_GLOBAL/SYSTEM pointed nowhere, so a developer's
`tag.gpgsign = true` cannot silently sign (or unsign) the tags these tests make.
"""

from __future__ import annotations

import json
import subprocess
import textwrap

import nuk
import pytest
import yaml

HELLO = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: hello}
spec:
  placement: {role: app}
  ingress:
    - {host: hello.bitcoinalchemist.com, service: web, port: 8080}
"""

ROGUE = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: rogue}
spec:
  placement: {role: app}
"""

ORG = """\
apiVersion: nukorg/v1
kind: Org
metadata: {name: astrojones}
domains: [bitcoinalchemist.com]
platformDomain: bitcoinalchemist.com
acmeEmail: admin@bitcoinalchemist.com
network:
  cidr: 10.0.0.0/16
  cloudSubnet: 10.0.0.0/16
  vswitchSubnet: 10.0.20.0/24
  vswitchVlan: 4001
hosts:
  - {name: ingress, provider: hcloud, role: edge, privateIp: 10.0.10.241}
  - {name: deploy, provider: hcloud, role: app, privateIp: 10.0.11.10}
facilities:
  dns: wildcard
  tls: dns01
  dnsProvider: hetzner
  secrets: sops
  auth: authentik
  runners: ephemeral
mesh: tailscale
"""

TENANTS = """\
tenants:
  - name: astrojones
    edge: shared
    domains: [hello.bitcoinalchemist.com, pd.jonaheidsick.de, fasdemo.jonaheidsick.de]
    signer_principal: astrojones
"""

BASIC_FACILITY = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: basic-auth}
spec:
  placement: {role: edge}
  provides:
    route: {capability: basic, middlewares: [auth@file]}
"""

DATA_STACK = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: data-stack}
spec:
  placement: {role: data}
  compose: docker-compose.data.yml
  provides:
    env: {capability: databases, bind: postgres}
  health: {containers: [nuk-postgres, nuk-redis]}
"""

KOLBE = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: kolbe}
spec:
  placement: {role: app}
  ingress:
    - {host: kolbe.astrojones.guru, service: web, port: 8080}
"""

# Two tenants that own separate zones; kolbeapp-de is the target of astrojones's loan.
ZONE_TENANTS = """\
tenants:
  - name: astrojones
    edge: shared
    domains: [astrojones.guru, "*.astrojones.guru"]
    signer_principal: astrojones
  - name: kolbeapp-de
    edge: shared
    domains: [kolbeapp.de, "*.kolbeapp.de"]
    signer_principal: kolbeapp-de
"""

DELEGATING = """\
apiVersion: nuk/v1
kind: Delegations
metadata: {name: astrojones}
spec:
  delegations:
    - {host: kolbe.astrojones.guru, to: kolbeapp-de}
"""


@pytest.fixture
def platform_files() -> dict[str, str]:
    """The files of the platform (bartixcloud/infra) tree as relative path -> content."""
    return {
        nuk.DEFAULT_ORG_FILE: ORG,
        "tenants.yml": TENANTS,
        "facilities/basic.yml": BASIC_FACILITY,
        "facilities/data-stack.yml": DATA_STACK,
    }


@pytest.fixture(autouse=True)
def _hermetic_git(tmp_path, monkeypatch):
    nowhere = str(tmp_path / "no-such-gitconfig")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", nowhere)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", nowhere)


def _run(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


class Origin:
    """A work repo plus its bare origin; `release` commits files and pushes a tag."""

    def __init__(self, root, name, pubkey):
        """Create the work repo and an empty bare origin it pushes to."""
        self.work = root / f"{name}-work"
        self.bare = root / f"{name}.git"
        self.pubkey = pubkey
        self.work.mkdir()
        _run("git", "init", "-q", "-b", "main", cwd=self.work)
        _run("git", "config", "user.email", "t@example.invalid", cwd=self.work)
        _run("git", "config", "user.name", "T", cwd=self.work)
        _run("git", "init", "--bare", "-q", str(self.bare))
        _run("git", "remote", "add", "origin", str(self.bare), cwd=self.work)

    def release(self, tag, files, *, sign=True):
        """Commit `files`, tag HEAD (SSH-signed unless sign=False), push; return the commit."""
        for rel, body in files.items():
            path = self.work / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(body), encoding="utf-8")
        _run("git", "add", "-A", cwd=self.work)
        _run("git", "commit", "-qm", tag, "--allow-empty", cwd=self.work)
        self.tag_head(tag, sign=sign)
        return _run("git", "rev-parse", "HEAD", cwd=self.work).stdout.strip()

    def tag_head(self, tag, ref="HEAD", *, sign=True):
        if sign:
            argv = ["-c", "gpg.format=ssh", "-c", f"user.signingkey={self.pubkey}", "tag", "-s"]
        else:
            argv = ["-c", "tag.gpgSign=false", "tag", "-a"]
        _run("git", *argv, tag, ref, "-m", tag, cwd=self.work)
        _run("git", "push", "-q", "origin", "main", "--tags", "--force", cwd=self.work)

    def delete_tag(self, tag):
        _run("git", "tag", "-d", tag, cwd=self.work)
        _run("git", "-C", str(self.bare), "tag", "-d", tag)


@pytest.fixture(scope="module")
def signing_keys(tmp_path_factory):
    """One ed25519 key per source, generated once per module (ssh-keygen is the slow part)."""
    root = tmp_path_factory.mktemp("keys")
    keys = {}
    for name in ("bartixcloud", "astrojones", "kolbeapp-de"):
        key = root / f"key-{name}"
        _run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(key))
        keys[name] = key.with_suffix(".pub")
    return keys


class Fleet:
    """Origins, signers, a sources.yml and a state dir for one simulated host."""

    def __init__(self, root, platform_files, keys):
        """Publish v1.0.0 of the platform and astrojones repos, signed by their own keys."""
        self.root = root
        self.signers_dir = root / "allowed_signers.d"
        self.signers_dir.mkdir()
        self.state = root / "state"
        self.sources_file = root / "sources.yml"
        self.origins = {}
        for name, pub in keys.items():
            (self.signers_dir / name).write_text(
                f"{name} {pub.read_text(encoding='utf-8').strip()}\n", encoding="utf-8"
            )
            self.origins[name] = Origin(root, name, pub)
        self.origins["bartixcloud"].release("v1.0.0", platform_files)
        self.origins["astrojones"].release("v1.0.0", {"deployments/hello.yml": HELLO})
        self.use(("bartixcloud", ["facilities"]), ("astrojones", ["deployments"]))

    def use(self, *entries):
        """Write sources.yml from (name, apply) pairs."""
        doc = {
            "sources": [
                {
                    "name": name,
                    "repo": str(self.origins[name].bare),
                    "deploy_key": "/nonexistent/key",
                    "apply": apply,
                }
                for name, apply in entries
            ]
        }
        self.sources_file.write_text(yaml.safe_dump(doc), encoding="utf-8")

    def converge(self):
        return nuk.cmd_converge(
            sources_file=self.sources_file, signers_dir=self.signers_dir, state_dir=self.state
        )

    def status(self):
        return nuk.read_converge_status(self.state / "converge-status.json")

    def last_applied(self, name):
        path = nuk.source_state_dir(self.state, name) / "last-applied-tag"
        return path.read_text(encoding="utf-8").split() if path.exists() else None


@pytest.fixture
def fleet(tmp_path, monkeypatch, platform_files, signing_keys):
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "HOST_ENV", tmp_path / "no-host-env")
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.11.10"))
    f = Fleet(tmp_path, platform_files, signing_keys)
    f.applied = []
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: f.applied.append(path.stem))
    return f


# --- ordering, isolation, exit code -----------------------------------------------------


def test_the_platform_source_is_processed_first(fleet, capsys):
    fleet.use(("astrojones", ["deployments"]), ("bartixcloud", ["facilities"]))
    assert fleet.converge() == 0
    targets = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("target:")]
    assert [t.split()[1] for t in targets] == ["bartixcloud", "astrojones"]
    assert list(fleet.status()["sources"]) == ["bartixcloud", "astrojones"]


def test_each_source_records_its_own_last_applied_tag(fleet):
    assert fleet.converge() == 0
    for name in ("bartixcloud", "astrojones"):
        tag, sha = fleet.last_applied(name)
        assert tag == "v1.0.0"
        want = _run("git", "rev-parse", "HEAD", cwd=fleet.origins[name].work).stdout.strip()
        assert sha == want


def test_a_tenant_manifest_is_applied_and_a_tenant_facility_is_not(fleet):
    fleet.origins["astrojones"].release("v1.1.0", {"facilities/rogue.yml": ROGUE})
    assert fleet.converge() == 0
    assert fleet.applied == ["hello"]  # rogue is placed on `app` too, but never read


def test_a_refusing_source_does_not_stop_another(fleet, capsys):
    fleet.origins["kolbeapp-de"].release("v1.0.0", {"deployments/x.yml": HELLO}, sign=False)
    fleet.use(
        ("bartixcloud", ["facilities"]),
        ("kolbeapp-de", ["deployments"]),
        ("astrojones", ["deployments"]),
    )
    assert fleet.converge() == 1
    sources = fleet.status()["sources"]
    assert sources["kolbeapp-de"]["result"] == "refused"
    assert "no v* tag verifies" in sources["kolbeapp-de"]["error"]
    assert sources["astrojones"]["result"] == "ok"
    assert "hello" in fleet.applied
    assert "REFUSING source kolbeapp-de" in capsys.readouterr().err
    assert fleet.last_applied("kolbeapp-de") is None


def test_the_exit_code_is_zero_when_a_manifest_fails_but_every_source_verified(fleet, monkeypatch):
    def flaky(path, _rp, **_k):
        if path.stem == "hello":
            raise subprocess.CalledProcessError(1, ["docker"])

    monkeypatch.setattr(nuk, "cmd_apply", flaky)
    assert fleet.converge() == 0
    manifests = fleet.status()["sources"]["astrojones"]["manifests"]
    assert [(m["name"], m["result"]) for m in manifests] == [("hello", "failed")]


def test_tenant_sources_are_refused_when_the_platform_does_not_verify(fleet):
    origin = fleet.origins["bartixcloud"]
    origin.delete_tag("v1.0.0")
    origin.release("v1.1.0", {"x": "1\n"}, sign=False)
    assert fleet.converge() == 1
    sources = fleet.status()["sources"]
    assert sources["bartixcloud"]["result"] == "refused"
    assert "did not verify this cycle" in sources["astrojones"]["error"]
    assert fleet.applied == []


def test_a_platform_tree_without_org_is_refused_and_tenants_follow(
    tmp_path, monkeypatch, platform_files, signing_keys
):
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.11.10"))
    monkeypatch.setattr(nuk, "cmd_apply", lambda *_a, **_k: pytest.fail("must not apply"))
    incomplete = {k: v for k, v in platform_files.items() if k != nuk.DEFAULT_ORG_FILE}
    f = Fleet(tmp_path, incomplete, signing_keys)
    assert f.converge() == 1
    sources = f.status()["sources"]
    assert "lacks" in sources["bartixcloud"]["error"]
    assert "did not verify this cycle" in sources["astrojones"]["error"]
    assert f.last_applied("bartixcloud") is None


# --- trust ------------------------------------------------------------------------------


def test_a_tag_signed_with_another_sources_key_is_refused(fleet):
    other = fleet.origins["kolbeapp-de"]
    fleet.origins["astrojones"].delete_tag("v1.0.0")
    fleet.origins["astrojones"].pubkey = other.pubkey
    fleet.origins["astrojones"].tag_head("v1.0.0")
    assert fleet.converge() == 1
    assert "no v* tag verifies" in fleet.status()["sources"]["astrojones"]["error"]


def test_a_missing_signers_file_refuses_that_source_only(fleet):
    (fleet.signers_dir / "astrojones").unlink()
    assert fleet.converge() == 1
    sources = fleet.status()["sources"]
    assert "trust anchor" in sources["astrojones"]["error"]
    assert sources["bartixcloud"]["result"] == "ok"


def test_a_downgrade_is_refused_and_the_prior_state_untouched(fleet):
    origin = fleet.origins["astrojones"]
    origin.release("v1.1.0", {"deployments/more.yml": HELLO.replace("hello", "more")})
    assert fleet.converge() == 0
    before = fleet.last_applied("astrojones")
    assert before[0] == "v1.1.0"
    origin.delete_tag("v1.1.0")
    assert fleet.converge() == 1
    assert "not a descendant" in fleet.status()["sources"]["astrojones"]["error"]
    assert fleet.last_applied("astrojones") == before


def test_a_new_tag_on_an_old_commit_is_refused(fleet):
    """The deletion attack's shape: drop the applied tag, sign a new one on the OLD commit."""
    origin = fleet.origins["astrojones"]
    old = _run("git", "rev-parse", "HEAD", cwd=origin.work).stdout.strip()
    origin.release("v1.1.0", {"deployments/more.yml": HELLO.replace("hello", "more")})
    assert fleet.converge() == 0
    origin.delete_tag("v1.1.0")
    origin.tag_head("v1.2.0", old)
    assert fleet.converge() == 1
    assert "not a descendant" in fleet.status()["sources"]["astrojones"]["error"]
    assert fleet.last_applied("astrojones")[0] == "v1.1.0"


def test_a_revert_commit_rolls_a_source_back(fleet):
    origin = fleet.origins["astrojones"]
    origin.release("v1.1.0", {"deployments/more.yml": HELLO.replace("hello", "more")})
    assert fleet.converge() == 0
    _run("git", "revert", "--no-edit", "HEAD", cwd=origin.work)
    origin.tag_head("v1.2.0")
    fleet.applied.clear()
    assert fleet.converge() == 0
    assert fleet.last_applied("astrojones")[0] == "v1.2.0"
    assert fleet.applied.count("more") == 0


def test_the_tree_comes_from_the_commit_not_a_worktree(fleet, monkeypatch):
    seen = []

    def spy(path, _rp, **_k):
        seen.append(path.read_text(encoding="utf-8"))

    monkeypatch.setattr(nuk, "cmd_apply", spy)
    (fleet.origins["astrojones"].work / "deployments" / "hello.yml").write_text("UNCOMMITTED\n")
    assert fleet.converge() == 0
    assert all("UNCOMMITTED" not in text for text in seen)


# --- lock and status --------------------------------------------------------------------


def test_the_lock_makes_the_cycle_a_clean_no_op(fleet):
    with nuk.converge_lock(fleet.state) as acquired:
        assert acquired is True
        assert fleet.converge() == 0
    assert fleet.applied == []
    assert fleet.status() is None


def test_the_status_has_the_c3_shape(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "read_tenant", lambda: "astrojones")
    assert fleet.converge() == 0
    data = fleet.status()
    assert set(data) == {"role", "tenant", "appliedAt", "reapWarnings", "sources"}
    assert (data["role"], data["tenant"], data["reapWarnings"]) == ("app", "astrojones", [])
    assert data["appliedAt"].endswith("Z")
    block = data["sources"]["astrojones"]
    assert set(block) == {
        "result",
        "error",
        "tag",
        "commit",
        "apply",
        "manifests",
        "rendered",
        "refusedRoutes",
    }
    assert block["apply"] == ["deployments"]
    assert block["manifests"] == [
        {"name": "hello", "kind": "Deployment", "result": "ok", "error": None}
    ]


def test_an_unreadable_sources_file_still_writes_a_status(fleet, capsys):
    fleet.sources_file.write_text("sources: []\n", encoding="utf-8")
    assert fleet.converge() == 1
    data = fleet.status()
    assert data["sources"] == {}
    assert "sources" in data["error"]
    assert "REFUSING" in capsys.readouterr().err


def test_an_unexpected_exception_still_leaves_a_status(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "reap_report", lambda *_t: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        fleet.converge()
    assert set(fleet.status()["sources"]) == {"bartixcloud", "astrojones"}


# --- the edge: the logging line (spec §14.3) --------------------------------------------


def test_the_edge_records_the_logging_facility_health(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(
        nuk, "env_facility", lambda facilities, cap: facilities[0] if cap == "logs" else None
    )
    monkeypatch.setattr(nuk, "facility_health", lambda manifest: None)
    assert fleet.converge() == 0
    assert fleet.status()["logging"] == {"healthy": True, "detail": "ok"}


def test_an_unhealthy_logging_facility_is_recorded_not_refused(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "env_facility", lambda facilities, cap: facilities[0])
    monkeypatch.setattr(nuk, "facility_health", lambda m: "container 'loki' is not running")
    assert fleet.converge() == 0
    logging = fleet.status()["logging"]
    assert logging["healthy"] is False
    assert "loki" in logging["detail"]


def test_a_non_edge_host_records_no_logging_line(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "facility_health", lambda m: pytest.fail("not off the edge"))
    assert fleet.converge() == 0
    assert "logging" not in fleet.status()


# --- the edge: the tenant domain allowlist (spec §4 anti-hijack) ------------------------


def _edge_routes(fleet, monkeypatch):
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    fleet.use(("bartixcloud", ["facilities"]), ("astrojones", ["deployments", "routes"]))


def test_a_tenant_route_in_its_domains_is_rendered(fleet, monkeypatch):
    _edge_routes(fleet, monkeypatch)
    assert fleet.converge() == 0
    block = fleet.status()["sources"]["astrojones"]
    assert block["rendered"] == ["hello"]
    assert block["refusedRoutes"] == []
    assert (nuk.DYNAMIC / "hello.yml").is_file()


def test_a_tenant_route_for_a_foreign_host_is_refused(fleet, monkeypatch):
    _edge_routes(fleet, monkeypatch)
    fleet.origins["astrojones"].release(
        "v1.1.0",
        {
            "deployments/steal.yml": HELLO.replace(
                "hello.bitcoinalchemist.com", "kolbeapp.de"
            ).replace("name: hello", "name: steal")
        },
    )
    assert fleet.converge() == 0
    block = fleet.status()["sources"]["astrojones"]
    assert block["rendered"] == ["hello"]  # only the in-domain route
    assert block["refusedRoutes"] == [
        "REFUSED route kolbeapp.de: owned/delegated by the platform"
    ]
    assert not (nuk.DYNAMIC / "steal.yml").exists()
    assert (nuk.DYNAMIC / "hello.yml").is_file()


def test_a_tenant_missing_from_the_registry_routes_nothing(
    tmp_path, monkeypatch, platform_files, signing_keys
):
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "cmd_apply", lambda *_a, **_k: None)
    no_tenants = {k: v for k, v in platform_files.items() if k != "tenants.yml"}
    f = Fleet(tmp_path, no_tenants, signing_keys)
    f.use(("bartixcloud", ["facilities"]), ("astrojones", ["deployments", "routes"]))
    assert f.converge() == 0
    block = f.status()["sources"]["astrojones"]
    assert block["rendered"] == []
    assert block["refusedRoutes"] == [
        "REFUSED route hello.bitcoinalchemist.com: owned/delegated by the platform"
    ]


def test_delegation_from_a_later_source_is_effective_in_the_same_cycle(
    tmp_path, monkeypatch, signing_keys
):
    """A delegation from a later source is effective in the same cycle (spec §3.5).

    The owner astrojones (source 2) lends kolbe.astrojones.guru to kolbeapp-de (source 1),
    which is processed FIRST; the loan — verified later in the same cycle — must already
    authorize the render.
    """
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "HOST_ENV", tmp_path / "no-host-env")
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "cmd_apply", lambda *_a, **_k: None)
    platform = {nuk.DEFAULT_ORG_FILE: ORG, "tenants.yml": ZONE_TENANTS}
    f = Fleet(tmp_path, platform, signing_keys)
    f.origins["kolbeapp-de"].release("v1.0.0", {"deployments/kolbe.yml": KOLBE})
    f.origins["astrojones"].release("v1.1.0", {nuk.DELEGATIONS_FILE: DELEGATING})
    f.use(
        ("bartixcloud", ["facilities"]),
        ("kolbeapp-de", ["deployments", "routes"]),
        ("astrojones", ["deployments"]),
    )
    assert f.converge() == 0
    block = f.status()["sources"]["kolbeapp-de"]
    assert block["refusedRoutes"] == []
    assert block["rendered"] == ["kolbe"]
    assert (nuk.DYNAMIC / "kolbe.yml").is_file()


# --- reap -------------------------------------------------------------------------------


def test_orphans_are_reported_across_all_trees_and_never_deleted(fleet, tmp_path, capsys):
    deploys = tmp_path / "deploys"
    for name in ("hello", "basic-auth", "data-stack", "legacy"):
        (deploys / name).mkdir(parents=True)
    assert fleet.converge() == 0
    assert fleet.status()["reapWarnings"] == ["legacy"]
    assert (deploys / "legacy").is_dir()
    assert "WARN: 1 deployed app(s) not declared by any source: legacy" in capsys.readouterr().out


def test_no_orphan_report_when_a_source_was_refused(fleet, tmp_path):
    (tmp_path / "deploys" / "hello").mkdir(parents=True)
    (fleet.signers_dir / "astrojones").unlink()
    assert fleet.converge() == 1
    assert fleet.status()["reapWarnings"] == []


def test_status_json_is_plain_json(fleet):
    fleet.converge()
    json.loads((fleet.state / "converge-status.json").read_text(encoding="utf-8"))
