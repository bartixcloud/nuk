"""Frozen KDF + remote-URL contract for cross-host DB access (spec §3.1).

The KDF is spec-stable: a change here is a fleet-wide password rotation.
These tests pin the exact vectors so that change is deliberate, never accidental.
"""

import base64
import hashlib
import hmac

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
