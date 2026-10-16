"""Guards for nuk behaviour that fails silently when it breaks.

Three of these pin changes that landed with no coverage at all:

  * `write_ingress` skips a byte-identical rewrite. Every write is an fsnotify
    event that makes Traefik rebuild its whole dynamic config, and the loop
    re-applies every cycle.
  * `_annotate_routers` probes hosts concurrently — serially, one dead host
    costs the full 2.5 s timeout before the next is even tried.
  * `cmd_apply` on an existing checkout pulls without a preceding fetch.

The rest pin the contracts of the helpers the apply and render paths lean on,
and the publish/backend port agreement: if `build_override` publishes on a port
`backend_address` does not dial, a router points at nothing and nothing errors.

Each behavioural claim is asserted through the *caller*, not the helper, so it
stays true if the helper is inlined again.
"""

from __future__ import annotations

import textwrap
import threading
import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import nuk

ORG = """
    apiVersion: nukorg/v1
    kind: Org
    metadata: {name: astrojones}
    domains: [example.com]
    platformDomain: example.com
    acmeEmail: admin@example.com
    network:
      cidr: 10.0.0.0/16
      cloudSubnet: 10.0.1.0/24
      vswitchSubnet: 10.0.10.0/24
      vswitchVlan: 4001
    hosts:
      - {name: metal,   provider: manual, role: hypervisor, privateIp: 10.0.2.2}
      - {name: ingress, provider: incus, role: edge, privateIp: 10.0.10.241, metal: metal}
      - {name: deploy,  provider: incus, role: app,  privateIp: 10.0.10.107, metal: metal}
      - {name: db,      provider: incus, role: data, privateIp: 10.0.10.180, metal: metal}
    facilities:
      dns: wildcard
      tls: dns01
      dnsProvider: hetzner
      secrets: sops
      auth: basic
      runners: none
"""

DEPLOYMENT = """
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: app}
    spec:
      source: {repo: "https://github.com/astrojones/example", branch: main}
      placement: {role: app}
      ingress:
        - {host: app.example.com, service: web, port: 8080}
"""


TWO_APP_HOSTS_ORG = {
    "apiVersion": "nukorg/v1",
    "kind": "Org",
    "metadata": {"name": "astrojones"},
    "domains": ["jonaheidsick.de"],
    "platformDomain": "jonaheidsick.de",
    "acmeEmail": "admin@jonaheidsick.de",
    "hosts": [
        {
            "name": "ingress",
            "provider": "incus",
            "metal": "metal",
            "role": "edge",
            "privateIp": "10.0.10.241",
        },
        {
            "name": "metal",
            "provider": "manual",
            "ip": "1.2.3.4",
            "role": "hypervisor",
            "privateIp": "10.0.2.2",
        },
        {
            "name": "deploy",
            "provider": "incus",
            "metal": "metal",
            "role": "app",
            "privateIp": "10.0.10.107",
        },
        {
            "name": "kolbe-app",
            "provider": "incus",
            "metal": "metal",
            "role": "app",
            "privateIp": "10.0.10.190",
        },
    ],
    "facilities": {
        "dns": "wildcard",
        "tls": "dns01",
        "dnsProvider": "hetzner",
        "secrets": "sops",
        "runners": "ephemeral",
    },
}


def _load(tmp_path: Path, body: str, name: str):
    doc = tmp_path / name
    doc.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return doc


# --- helper contracts ---------------------------------------------------------


def test_read_env_file_parses_the_key_value_contract(tmp_path):
    env = tmp_path / "x.env"
    env.write_text(
        "# comment\n\nA=1\n  B  =  2  \nC=with=equals\nEMPTY=\nno_equals_here\n",
        encoding="utf-8",
    )
    assert nuk._read_env_file(env) == {
        "A": "1",
        "B": "2",
        "C": "with=equals",
        "EMPTY": "",
    }


def test_read_env_file_raises_on_a_missing_file(tmp_path):
    """The contract the three call sites rely on: OSError, not a silent {}."""
    with pytest.raises(OSError):
        nuk._read_env_file(tmp_path / "absent.env")


def test_read_json_safe_never_raises(tmp_path):
    assert nuk._read_json_safe(tmp_path / "absent.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert nuk._read_json_safe(bad) is None
    good = tmp_path / "good.json"
    good.write_text('{"a": 1}', encoding="utf-8")
    assert nuk._read_json_safe(good) == {"a": 1}


def test_git_try_is_none_on_every_failure_mode(tmp_path):
    assert nuk._git_try(tmp_path, "rev-parse", "HEAD") is None  # not a repo
    assert nuk._git_try(tmp_path, "definitely-not-a-subcommand") is None


def test_git_try_returns_stripped_stdout_in_a_real_repo(tmp_path):
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S607
    assert nuk._git_try(tmp_path, "rev-parse", "--is-inside-work-tree") == "true"


def test_result_builds_one_converge_status_entry():
    assert nuk._result("x", "Deployment") == {
        "name": "x",
        "kind": "Deployment",
        "result": "ok",
        "error": None,
    }
    assert nuk._result("x", "Facility", "refused", "why") == {
        "name": "x",
        "kind": "Facility",
        "result": "refused",
        "error": "why",
    }


def test_exit_reason_prefers_the_carried_message():
    assert nuk._exit_reason(SystemExit("boom"), "default") == "boom"
    assert nuk._exit_reason(SystemExit(), "default") == "default"
    assert nuk._exit_reason(SystemExit(None), "default") == "default"


def test_url_helpers():
    assert nuk._pg_url("a", "pw", "h", None) == "postgresql://a:pw@h:5432/a"
    assert nuk._pg_url("a", "pw", "h", "psycopg") == "postgresql+psycopg://a:pw@h:5432/a"
    assert nuk._redis_url("a", "pw", "h") == "redis://a:pw@h:6379/0"


def test_pg_driver_reads_only_a_string():
    assert nuk._pg_driver({"driver": "asyncpg"}) == "asyncpg"
    assert nuk._pg_driver(True) is None  # bare `postgres: true`
    assert nuk._pg_driver(None) is None


def test_pg_driver_ignores_a_non_string_value():
    """A non-string driver would be interpolated verbatim into the URL."""
    assert nuk._pg_driver({"driver": 5}) is None


def test_db_env_apps_lists_only_creds_files(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    (tmp_path / "b-db.env").write_text("", encoding="utf-8")
    (tmp_path / "a-db.env").write_text("DATABASE_URL=x\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    assert nuk._db_env_apps() == ["a", "b"]


def test_db_env_apps_is_empty_without_the_secrets_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "SECRETS", tmp_path / "absent")
    assert nuk._db_env_apps() == []


def test_host_for_finds_the_role_host_and_returns_none_otherwise(tmp_path):
    org = nuk.load_org(_load(tmp_path, ORG, "org.yml"))
    assert org.host_for("app").private_ip == "10.0.10.107"  # type: ignore[union-attr]
    assert org.host_for("nope") is None


def test_host_named_finds_by_name(tmp_path):
    org = nuk.Org.model_validate(TWO_APP_HOSTS_ORG)
    assert org.host_named("kolbe-app").private_ip == "10.0.10.190"  # type: ignore[union-attr]
    assert org.host_named("nope") is None


# --- the published-port invariant ---------------------------------------------


def test_host_port_is_the_same_number_on_the_publish_and_the_backend(tmp_path):
    """build_override publishes on hostPort-or-port; backend_address must dial it.

    `_published_port` exists to keep the two in step. A divergence here is a
    router pointing at a port nothing is bound to — silence, not an error.
    """
    org = nuk.load_org(_load(tmp_path, ORG, "org.yml"))
    manifest = nuk.Deployment.model_validate(
        {
            "apiVersion": "nuk/v1",
            "kind": "Deployment",
            "metadata": {"name": "app"},
            "spec": {
                "source": {"repo": "https://github.com/astrojones/example"},
                "placement": {"role": "app"},
                "ingress": [{"host": "app.example.com", "service": "web", "port": 8080}],
            },
        }
    )

    for ing in (
        {"host": "app.example.com", "service": "web", "port": 8080},
        {"host": "app.example.com", "service": "web", "port": 8080, "hostPort": 18080},
    ):
        expected = ing.get("hostPort") or ing["port"]
        assert nuk.backend_address(org, manifest, ing) == f"10.0.10.107:{expected}"
        ov = nuk.build_override("app", [ing], publish_ip="10.0.10.107")
        assert f"10.0.10.107:{expected}:{ing['port']}" in ov["services"]["web"]["ports"]


def test_published_port_is_host_port_or_port():
    assert nuk._published_port(nuk.Ingress(host="h", service="s", port=8080)) == 8080
    assert nuk._published_port(nuk.Ingress(host="h", service="s", port=8080, hostPort=18080)) == (
        18080
    )
    assert nuk._published_port(nuk.Ingress(host="h", service="s", port=8080, hostPort=0)) == 8080


# --- the idempotent Traefik write ---------------------------------------------


def _web(host: str) -> nuk.Ingress:
    return nuk.Ingress.model_validate({"host": host, "service": "web", "port": 8080})


def test_write_ingress_skips_a_byte_identical_rewrite(tmp_path, monkeypatch):
    """A rewrite every cycle is an fsnotify event every cycle.

    A read-only target makes the assertion unambiguous: a second identical call
    must not attempt a write at all.
    """
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path)
    ingress = [_web("a.example.com")]
    nuk.write_ingress("app", ingress, {})
    target = tmp_path / "app.yml"
    assert target.exists()
    target.chmod(0o444)
    nuk.write_ingress("app", ingress, {})  # identical -> no write, no error
    assert target.read_text(encoding="utf-8")


def test_write_ingress_still_writes_changed_content(tmp_path, monkeypatch):
    """The other half of the guard: it is content-compared, not write-once."""
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path)
    nuk.write_ingress("app", [_web("a.example.com")], {})
    target = tmp_path / "app.yml"
    first = target.read_text(encoding="utf-8")
    nuk.write_ingress("app", [_web("b.example.com")], {})
    assert target.read_text(encoding="utf-8") != first


def test_write_ingress_removes_the_file_when_the_render_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path)
    nuk.write_ingress("app", [_web("a.example.com")], {})
    target = tmp_path / "app.yml"
    assert target.exists()
    nuk.write_ingress("app", [], {})
    assert not target.exists()


# --- the concurrent router probe ----------------------------------------------


def test_annotate_routers_probes_hosts_concurrently(monkeypatch):
    """Serially, one unreachable host costs its full 2.5 s timeout before the
    next is tried.

    Asserts observed overlap rather than wall-clock, so a slow machine cannot
    make it flap.
    """
    hosts = [f"h{i}.example.com" for i in range(16)]
    lock = threading.Lock()
    inflight = 0
    peak = 0

    def probe(host: str, timeout: float = 2.5) -> str:
        nonlocal inflight, peak
        with lock:
            inflight += 1
            peak = max(peak, inflight)
        time.sleep(0.05)
        with lock:
            inflight -= 1
        return "enabled"

    monkeypatch.setattr(nuk, "_probe", probe)
    routers = [{"rule": f"Host(`{h}`)"} for h in hosts]
    out = nuk._annotate_routers(routers, hosts)

    assert peak >= 2, f"probes never overlapped (peak={peak}) — the pool is not in use"
    assert [r["live"] for r in out] == ["enabled"] * len(hosts)


def test_annotate_routers_keeps_the_host_matching_and_the_none_case(monkeypatch):
    hosts = ["a.example.com", "b.example.com"]
    monkeypatch.setattr(nuk, "_probe", lambda h, timeout=2.5: f"live:{h}")
    out = nuk._annotate_routers(
        [
            {"rule": "Host(`a.example.com`)"},
            {"rule": "Host(`b.example.com`) && PathPrefix(`/x`)"},
        ],
        hosts,
    )
    assert [r["live"] for r in out] == ["live:a.example.com", "live:b.example.com"]

    out = nuk._annotate_routers([{"rule": "Host(`zzz.example.com`)"}], hosts)
    assert out[0]["live"] is None

    assert nuk._annotate_routers(None, hosts) == []


# --- the cmd_apply git flow ---------------------------------------------------


def _stub_apply(tmp_path: Path, monkeypatch, calls: list[tuple]) -> None:
    """Stub everything cmd_apply touches outside the tree, capturing sh()."""
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tmp_path / "proj" / name)
    monkeypatch.setattr(nuk, "sh", lambda *a, **_k: calls.append(a))
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("app", "10.0.10.107"))
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["true"])
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)


def _git_calls(calls: list[tuple]) -> list[list[str]]:
    return [list(c) for c in calls if c and c[0] == "git"]


def test_apply_existing_checkout_unpinned_does_not_fetch_first(tmp_path, monkeypatch):
    """`git pull` fetches on its own, so a preceding `git fetch` is a second
    network round trip on every converge cycle.
    """
    calls: list[tuple] = []
    _stub_apply(tmp_path, monkeypatch, calls)
    doc = _load(tmp_path, DEPLOYMENT, "app.yml")
    repo = tmp_path / "proj" / "app" / "repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()

    nuk.cmd_apply(doc, None)

    git = _git_calls(calls)
    assert git == [
        ["git", "-C", str(repo), "checkout", "main"],
        ["git", "-C", str(repo), "pull", "--ff-only", "--quiet"],
    ], git


def test_apply_pinned_checkout_fetches_then_detaches(tmp_path, monkeypatch):
    """Parity: the rollback path is unchanged — fetch, then detach. No pull."""
    calls: list[tuple] = []
    _stub_apply(tmp_path, monkeypatch, calls)
    doc = _load(tmp_path, DEPLOYMENT, "app.yml")
    repo = tmp_path / "proj" / "app" / "repo"
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()

    nuk.cmd_apply(doc, None, pin_commit="deadbeef")

    git = _git_calls(calls)
    assert git == [
        ["git", "-C", str(repo), "fetch", "--quiet"],
        ["git", "-C", str(repo), "checkout", "--quiet", "--detach", "deadbeef"],
    ], git


def test_apply_fresh_checkout_clones_at_the_branch(tmp_path, monkeypatch):
    """Parity: no checkout exists yet -> clone at the branch, never fetch."""
    calls: list[tuple] = []
    _stub_apply(tmp_path, monkeypatch, calls)
    doc = _load(tmp_path, DEPLOYMENT, "app.yml")

    nuk.cmd_apply(doc, None)

    git = _git_calls(calls)
    assert len(git) == 1
    assert git[0][:4] == ["git", "clone", "--branch", "main"]
    assert git[0][4] == "https://github.com/astrojones/example"
