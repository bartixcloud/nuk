"""Frozen KDF + remote-URL contract for cross-host DB access (spec §3.1).

The KDF is spec-stable: a change here is a fleet-wide password rotation.
These tests pin the exact vectors so that change is deliberate, never accidental.
"""

import base64
import hashlib
import hmac
import pathlib

import nuk


def _hkdf_sha256(seed: bytes, info: bytes) -> bytes:
    # RFC 5869 with salt=b"" and empty context, single block (32 bytes <= HashLen).
    prk = hmac.new(b"\x00" * 32, seed, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def test_derive_pg_vector_is_stable():
    seed = b"\x01" * 32
    expected = base64.urlsafe_b64encode(
        _hkdf_sha256(seed, b"nuk-db:pg:hello")
    ).rstrip(b"=").decode()
    assert nuk.derive_db_password(seed, "pg", "hello") == expected


def test_derive_redis_vector_is_stable():
    seed = b"\x02" * 32
    expected = base64.urlsafe_b64encode(
        _hkdf_sha256(seed, b"nuk-db:redis:hello")
    ).rstrip(b"=").decode()
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
    monkeypatch.setattr(nuk, "DB_SEED_ENV", tmp_path / "nope.env")
    assert nuk.load_db_seed() is None


def test_load_db_seed_reads_value(tmp_path, monkeypatch):
    p = tmp_path / "db-seed.env"
    p.write_text("NUK_DB_SEED=abc123\n")
    monkeypatch.setattr(nuk, "DB_SEED_ENV", p)
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
    monkeypatch.setattr(nuk, "SECRETS", tmp_path)
    monkeypatch.setattr(nuk, "load_db_seed", lambda: seed)
    monkeypatch.setattr(nuk, "_chown_deploy", lambda p: None)

    def _boom(*a, **k):
        msg = "remote mode must not touch the local data stack"
        raise AssertionError(msg)

    monkeypatch.setattr(nuk, "preflight_data_stack", _boom)
    monkeypatch.setattr(nuk, "ensure_postgres", _boom)
    monkeypatch.setattr(nuk, "ensure_redis", _boom)

    path = nuk.provision_databases(
        "hello", {"postgres": True, "redis": True}, [], remote_ip="10.0.10.180"
    )
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
        nuk.provision_databases("hello", {"postgres": True}, [], remote_ip="10.0.10.180")


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
                {"name": "nuroot-metal", "provider": "manual", "ip": "138.201.203.230",
                 "role": "hypervisor", "privateIp": "10.0.2.2"},
                {"name": "nuroot-db", "provider": "incus", "metal": "nuroot-metal",
                 "privateIp": "10.0.10.180", "role": "data"},
                {"name": "ingress", "provider": "incus", "metal": "nuroot-metal",
                 "privateIp": "10.0.10.241", "role": "edge"},
                {"name": "deploy", "provider": "incus", "metal": "nuroot-metal",
                 "privateIp": "10.0.10.107", "role": "app"},
            ],
            "facilities": {
                "dns": "wildcard", "tls": "dns01", "dnsProvider": "hetzner",
                "secrets": "sops", "auth": "authentik", "runners": "ephemeral",
            },
            "mesh": "none",
        }
    )
    assert nuk.data_host_ip(org) == "10.0.10.180"
