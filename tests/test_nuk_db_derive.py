"""Frozen KDF + remote-URL contract for cross-host DB access (spec §3.1).

The KDF is spec-stable: a change here is a fleet-wide password rotation.
These tests pin the exact vectors so that change is deliberate, never accidental.
"""

import base64
import hashlib
import hmac
import pathlib
import subprocess

import nuk


def _hkdf_sha256(seed: bytes, info: bytes) -> bytes:
    # RFC 5869 with salt=b"" and empty context, single block (32 bytes <= HashLen).
    prk = hmac.new(b"\x00" * 32, seed, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def test_kdf_literal_vectors_are_pinned():
    """Literal vectors: a change to BOTH helper and impl must still fail here.

    The KDF is spec-stable (spec §3.1) — a change here is a fleet-wide password
    rotation. These three values were frozen from the shipped implementation
    (`derive_db_password`), never invented, so they pin the exact bytes an
    independent HKDF reimplementation cannot vouch for.
    """
    seed32 = bytes(range(32))
    assert (
        nuk.derive_db_password(seed32, "pg", "hello")
        == "Kzb_gLQpy18VnJOKB7B_Q704RbGqmptj24wy5weNanA"
    )
    assert (
        nuk.derive_db_password(seed32, "redis", "hello")
        == "F5lCHlI6iOlVHTrF549ScdXxRHx0qG0Jls5xzfq4N5o"
    )
    assert (
        nuk.derive_db_password(b"\x00" * 32, "pg", "app-1")
        == "h6Pg7fU4P9HuNzrhGswIMIpo7IvKCFyg4j9UEHOukfk"
    )


def test_derive_pg_vector_is_stable():
    seed = b"\x01" * 32
    expected = (
        base64.urlsafe_b64encode(_hkdf_sha256(seed, b"nuk-db:pg:hello")).rstrip(b"=").decode()
    )
    assert nuk.derive_db_password(seed, "pg", "hello") == expected


def test_derive_redis_vector_is_stable():
    seed = b"\x02" * 32
    expected = (
        base64.urlsafe_b64encode(_hkdf_sha256(seed, b"nuk-db:redis:hello")).rstrip(b"=").decode()
    )
    assert nuk.derive_db_password(seed, "redis", "hello") == expected


def test_derive_labels_differ_by_kind_and_app():
    seed = b"\x03" * 32
    assert nuk.derive_db_password(seed, "pg", "a") != nuk.derive_db_password(seed, "redis", "a")
    assert nuk.derive_db_password(seed, "pg", "a") != nuk.derive_db_password(seed, "pg", "b")


def test_derive_password_is_url_safe_ascii():
    pw = nuk.derive_db_password(b"\x04" * 32, "pg", "app-1")
    assert pw.isascii()
    assert all(c.isalnum() or c in "-_" for c in pw)


def test_load_db_seed_absent_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(nuk.paths, "DB_SEED_ENV", tmp_path / "nope.env")
    assert nuk.load_db_seed() is None


def test_load_db_seed_reads_value(tmp_path, monkeypatch):
    p = tmp_path / "db-seed.env"
    p.write_text("NUK_DB_SEED=abc123\n")
    monkeypatch.setattr(nuk.paths, "DB_SEED_ENV", p)
    assert nuk.load_db_seed() == b"abc123"


def test_ensure_postgres_uses_derived_password_when_seeded(monkeypatch):
    seed = b"\x05" * 32
    monkeypatch.setattr(nuk, "load_db_seed", lambda: seed)
    calls = []
    monkeypatch.setattr(nuk, "_psql", lambda sql, db="postgres": calls.append(sql) or "")
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a, **k: None)
    url = nuk.ensure_postgres("hello", None)
    pw = nuk.derive_db_password(seed, "pg", "hello")
    assert pw in "".join(calls)  # the derived password was the one ALTERed in
    assert url == f"postgresql://hello:{pw}@nuk-postgres:5432/hello"


def test_ensure_redis_uses_derived_password_when_seeded(monkeypatch):
    seed = b"\x06" * 32
    monkeypatch.setattr(nuk, "load_db_seed", lambda: seed)
    calls = []
    monkeypatch.setattr(nuk, "_redis_admin", lambda *a: calls.append(a) or "")
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a, **k: None)
    url = nuk.ensure_redis("hello", None)
    pw = nuk.derive_db_password(seed, "redis", "hello")
    assert pw in " ".join(" ".join(map(str, a)) for a in calls)
    assert url == f"redis://hello:{pw}@nuk-redis:6379/0"


def test_remote_mode_writes_private_ip_urls(tmp_path, monkeypatch):
    seed = b"\x07" * 32
    monkeypatch.setattr(nuk.paths, "SECRETS", tmp_path)
    monkeypatch.setattr(nuk, "load_db_seed", lambda: seed)
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)

    def _boom(*a, **k):
        msg = "remote mode must not touch the local data stack"
        raise AssertionError(msg)

    monkeypatch.setattr(nuk, "preflight_data_stack", _boom)
    monkeypatch.setattr(nuk, "ensure_postgres", _boom)
    monkeypatch.setattr(nuk, "ensure_redis", _boom)

    dbs = nuk.Databases.model_validate({"postgres": True, "redis": True})
    path = nuk.provision_databases("hello", dbs, [], remote_ip="10.0.10.180")
    body = pathlib.Path(path).read_text(encoding="utf-8")
    pg = nuk.derive_db_password(seed, "pg", "hello")
    rd = nuk.derive_db_password(seed, "redis", "hello")
    assert f"DATABASE_URL=postgresql://hello:{pg}@10.0.10.180:5432/hello" in body
    assert f"REDIS_URL=redis://hello:{rd}@10.0.10.180:6379/0" in body


def test_remote_mode_without_seed_refuses(monkeypatch):
    monkeypatch.setattr(nuk, "load_db_seed", lambda: None)
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)
    import pytest

    with pytest.raises(SystemExit, match="seed"):
        nuk.provision_databases(
            "hello", nuk.Databases.model_validate({"postgres": True}), [], remote_ip="10.0.10.180"
        )


def test_data_host_ip_reads_org_role():
    org = nuk.Org.model_validate(
        {
            "apiVersion": "nukorg/v1",
            "kind": "Org",
            "metadata": {"name": "astrojones"},
            "domains": ["jonaheidsick.de"],
            "platformDomain": "jonaheidsick.de",
            "acmeEmail": "admin@jonaheidsick.de",
            "network": {
                "cidr": "10.0.0.0/16",
                "cloudSubnet": "10.0.1.0/24",
                "vswitchSubnet": "10.0.10.0/24",
                "vswitchVlan": 4001,
            },
            "hosts": [
                {
                    "name": "nuroot-metal",
                    "provider": "manual",
                    "ip": "138.201.203.230",
                    "role": "hypervisor",
                    "privateIp": "10.0.2.2",
                },
                {
                    "name": "nuroot-db",
                    "provider": "incus",
                    "metal": "nuroot-metal",
                    "privateIp": "10.0.10.180",
                    "role": "data",
                },
                {
                    "name": "ingress",
                    "provider": "incus",
                    "metal": "nuroot-metal",
                    "privateIp": "10.0.10.241",
                    "role": "edge",
                },
                {
                    "name": "deploy",
                    "provider": "incus",
                    "metal": "nuroot-metal",
                    "privateIp": "10.0.10.107",
                    "role": "app",
                },
            ],
            "facilities": {
                "dns": "wildcard",
                "tls": "dns01",
                "dnsProvider": "hetzner",
                "secrets": "sops",
                "runners": "ephemeral",
            },
            "mesh": "none",
        }
    )
    assert nuk.data_host_ip(org) == "10.0.10.180"


def _db_deployment(tmp_path, name, placement_role="app"):
    d = tmp_path / "deployments"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.yml").write_text(
        "apiVersion: nuk/v1\n"
        "kind: Deployment\n"
        f"metadata: {{name: {name}}}\n"
        "spec:\n"
        f"  placement: {{role: {placement_role}}}\n"
        "  databases:\n"
        "    postgres: true\n"
        "  ingress:\n"
        f"    - {{host: {name}.example.com, service: web, port: 8080}}\n",
        encoding="utf-8",
    )
    return tmp_path


def _ctx(tree, role):
    return nuk.TreeContext.build(tree, role, None, None, nuk.APPLY_ALL)


def _data_facility(tmp_path):
    f = tmp_path / "facilities"
    f.mkdir(parents=True, exist_ok=True)
    (f / "data-stack.yml").write_text(
        "apiVersion: nuk/v1\n"
        "kind: Facility\n"
        "metadata: {name: data-stack}\n"
        "spec:\n"
        "  placement: {role: data}\n"
        "  compose: docker-compose.data.yml\n"
        "  provides:\n"
        "    env: {capability: databases, bind: postgres}\n",
        encoding="utf-8",
    )
    (f / "data-stack").mkdir(exist_ok=True)
    (f / "data-stack" / "docker-compose.data.yml").write_text("services: {}\n", encoding="utf-8")
    return tmp_path


def test_capability_owner_provisions_a_placement_skipped_deployment(tmp_path, monkeypatch):
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    monkeypatch.setattr(nuk.paths, "SECRETS", tmp_path / "secrets")
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)
    monkeypatch.setattr(nuk, "load_db_seed", lambda: b"\x08" * 32)
    seen = []
    monkeypatch.setattr(
        nuk,
        "provision_databases",
        lambda app, dbs, facs, *, remote_ip=None: seen.append((app, remote_ip)) or "/x",
    )
    facs = nuk.load_facilities(tree)
    out = nuk.provision_remote_databases(tree, "data", facs)
    # placement says app, but the DATA host provisions it (spec §3.1 exception)
    assert seen == [("hello", None)]
    assert [r.to_wire() for r in out] == [
        {"name": "hello", "kind": "Database", "result": "ok", "error": None}
    ]


def test_non_owner_does_not_provision(tmp_path, monkeypatch):
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    monkeypatch.setattr(
        nuk,
        "provision_databases",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not provision")),
    )
    facs = nuk.load_facilities(tree)
    assert nuk.provision_remote_databases(tree, "edge", facs) == []
    assert nuk.provision_remote_databases(tree, "app", facs) == []


def test_sweep_is_idempotent_no_rotation(tmp_path, monkeypatch):
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    monkeypatch.setattr(nuk.paths, "SECRETS", tmp_path / "secrets")
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)
    seed = b"\x09" * 32
    monkeypatch.setattr(nuk, "load_db_seed", lambda: seed)
    calls = []
    monkeypatch.setattr(
        nuk,
        "ensure_postgres",
        lambda app, prev, driver=None: calls.append(prev) or "postgresql://x",
    )
    monkeypatch.setattr(nuk, "_psql", lambda *a, **k: "")
    monkeypatch.setattr(nuk, "preflight_data_stack", lambda *a, **k: None)
    facs = nuk.load_facilities(tree)
    nuk.provision_remote_databases(tree, "data", facs)
    nuk.provision_remote_databases(tree, "data", facs)
    # derived password is deterministic: the second cycle must converge identically
    assert len(calls) == 2


# --- final-review robustness fixes (I-1, I-4, I-3) --------------------------------


def test_sweep_catches_called_process_error_not_just_systemexit(tmp_path, monkeypatch):
    """I-4: `_psql` uses check=True, so a SQL failure raises CalledProcessError.

    The sweep must isolate it to this manifest's `failed` result (spec §7.5)
    rather than propagate out of apply_tree and abort the data host's cycle.
    """
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    monkeypatch.setattr(nuk.paths, "SECRETS", tmp_path / "secrets")
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)
    monkeypatch.setattr(nuk, "load_db_seed", lambda: b"\x0a" * 32)

    def boom(*_a, **_k):
        raise subprocess.CalledProcessError(1, ["docker", "exec", "nuk-postgres", "psql"])

    monkeypatch.setattr(nuk, "provision_databases", boom)
    out = nuk.provision_remote_databases(tree, "data", nuk.load_facilities(tree))
    assert [r.name for r in out] == ["hello"]
    assert out[0].result == "failed"
    assert out[0].error.startswith("provision failed:")


def test_apply_tree_survives_a_malformed_facility(tmp_path, monkeypatch):
    """I-1: a malformed facilities/*.yml must not abort apply_tree (spec §7.5).

    The sweep loads facilities as an argument; unguarded, `load` sys.exit
    propagates out of apply_tree and no converge-status.json is ever written —
    on every host. The malformed file is recorded as a failed Facility and the
    still-valid Facility is applied: results are still returned.
    """
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    (tree / "facilities" / "broken.yml").write_text("kind: Nonsense\n", encoding="utf-8")
    monkeypatch.setattr(nuk.paths, "SECRETS", tmp_path / "secrets")
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)
    applied = []
    monkeypatch.setattr(nuk, "cmd_apply", lambda path, _rp, **_k: applied.append(path.stem))
    results = nuk.apply_tree(_ctx(tree, "data"))  # must not raise
    by_name = {r.name: r for r in results}
    assert by_name["broken.yml"].result == "failed"
    assert "not a nuk/v1" in by_name["broken.yml"].error
    assert by_name["data-stack"].result == "ok"
    assert applied == ["data-stack"]


def _org_with_all_in_one_and_data(tmp_path):
    (tmp_path / nuk.DEFAULT_ORG_FILE).write_text(
        "apiVersion: nukorg/v1\n"
        "kind: Org\n"
        "metadata: {name: astrojones}\n"
        "domains: [example.com]\n"
        "platformDomain: example.com\n"
        "acmeEmail: admin@example.com\n"
        "hosts:\n"
        "  - {name: aio, provider: manual, privateIp: 10.0.10.10, role: all-in-one}\n"
        "  - {name: db, provider: manual, privateIp: 10.0.10.180, role: data}\n"
        "facilities: {dns: manual, tls: http01, secrets: generate, auth: basic, runners: none}\n"
        "mesh: tailscale\n",
        encoding="utf-8",
    )
    return tmp_path


def test_all_in_one_owner_derives_local_not_remote(tmp_path, monkeypatch):
    """I-3: the remote gate is capability ownership, not `role != "data"`.

    An `all-in-one` host owns every placement (placement_matches), so with a
    separate `data` host in the org it must still provision LOCALLY
    (remote_ip=None) — exactly mirroring provision_remote_databases's owner
    gate. The old `role != "data"` predicate would have derived remote here.
    """
    tree = _data_facility(_db_deployment(tmp_path, "hello"))
    _org_with_all_in_one_and_data(tree)
    (tree / "deployments" / "hello.yml").write_text(
        "apiVersion: nuk/v1\n"
        "kind: Deployment\n"
        "metadata: {name: hello}\n"
        "spec:\n"
        "  placement: {role: app}\n"
        "  source: {repo: 'https://github.com/astrojones/hello.git'}\n"
        "  databases: {postgres: true}\n"
        "  ingress:\n"
        "    - {host: hello.example.com, service: web, port: 8080}\n",
        encoding="utf-8",
    )
    doc = tree / "deployments" / "hello.yml"
    monkeypatch.setattr(nuk, "read_self", lambda: ("all-in-one", "10.0.10.10"))
    monkeypatch.setattr(nuk.paths, "DYNAMIC", tree / "dynamic")
    monkeypatch.setattr(nuk.paths, "DEPLOYS", tree / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: tree / "proj" / name)
    monkeypatch.setattr(nuk, "sh", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    seen = []
    monkeypatch.setattr(
        nuk,
        "provision_databases",
        lambda app, dbs, facs, *, remote_ip=None: seen.append(remote_ip) or None,
    )
    nuk.cmd_apply(doc, None)
    assert seen == [None]
