"""Provenance is a history, not a record (spec §8).

Pure filesystem + JSON — no docker, no network, no /opt/nuklaut. RELEASES and
DEPLOYS are monkeypatched to tmp_path, the same isolation pattern
test_nuk_status.py uses.
"""

from __future__ import annotations

import json
import subprocess

import nuk
import pydantic
import pytest


@pytest.fixture
def state(tmp_path, monkeypatch):
    """Point RELEASES (and DEPLOYS, for legacy seeds) at tmp dirs."""
    releases = tmp_path / "releases"
    deploys = tmp_path / "deployments"
    deploys.mkdir()
    monkeypatch.setattr(nuk, "RELEASES", releases)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    return releases, deploys


def _lines(path):
    """The parsed JSONL at `path`."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_write_creates_a_one_entry_history(state):
    releases, _ = state
    nuk.write_provenance(
        "hello", repo="git@github.com:a/b", branch="main", commit="a" * 40, image_digest="sha256:1"
    )
    entries = _lines(releases / "hello.jsonl")
    assert len(entries) == 1
    assert entries[0]["commit"] == "a" * 40


def test_append_preserves_the_earlier_entry(state):
    nuk.write_provenance("hello", repo="r", branch="main", commit="a" * 40, image_digest="sha256:1")
    nuk.write_provenance("hello", repo="r", branch="main", commit="b" * 40, image_digest="sha256:2")
    history = nuk.read_provenance_history("hello")
    assert [e.commit for e in history] == ["a" * 40, "b" * 40]


def test_read_provenance_returns_the_newest_entry(state):
    """The single-dict contract cmd_status and _overview_provenance depend on."""
    nuk.write_provenance("hello", repo="r", branch="main", commit="a" * 40, image_digest=None)
    nuk.write_provenance("hello", repo="r", branch="main", commit="b" * 40, image_digest=None)
    current = nuk.read_provenance("hello")
    assert current is not None
    assert current.commit == "b" * 40


def test_a_legacy_single_object_seeds_a_one_entry_history(state):
    """Files written by nuk <= 0.18 at DEPLOYS/<name>/provenance.json are a bare object."""
    _, deploys = state
    (deploys / "hello").mkdir()
    (deploys / "hello" / "provenance.json").write_text(
        json.dumps(
            {
                "repo": "r",
                "branch": "main",
                "commit": "a" * 40,
                "imageDigest": None,
                "appliedAt": "2026-01-01T00:00:00.000Z",
            }
        ),
        encoding="utf-8",
    )
    history = nuk.read_provenance_history("hello")
    assert len(history) == 1
    assert history[0].commit == "a" * 40


def test_a_legacy_list_seeds_the_history(state):
    """The interim 0.19 format at the same path was a JSON array."""
    _, deploys = state
    (deploys / "hello").mkdir()
    (deploys / "hello" / "provenance.json").write_text(
        json.dumps(
            [
                {
                    "repo": "r",
                    "branch": "main",
                    "commit": c,
                    "imageDigest": None,
                    "appliedAt": "2026-01-01T00:00:00.000Z",
                }
                for c in ("a" * 40, "b" * 40)
            ]
        ),
        encoding="utf-8",
    )
    assert [e.commit for e in nuk.read_provenance_history("hello")] == ["a" * 40, "b" * 40]


def test_appending_to_a_legacy_seed_writes_jsonl_and_leaves_the_seed_untouched(state):
    releases, deploys = state
    (deploys / "hello").mkdir()
    seed = {
        "repo": "r",
        "branch": "main",
        "commit": "a" * 40,
        "imageDigest": None,
        "appliedAt": "2026-01-01T00:00:00.000Z",
    }
    (deploys / "hello" / "provenance.json").write_text(json.dumps(seed), encoding="utf-8")
    nuk.write_provenance("hello", repo="r", branch="main", commit="b" * 40, image_digest=None)
    assert [e["commit"] for e in _lines(releases / "hello.jsonl")] == ["a" * 40, "b" * 40]
    assert json.loads((deploys / "hello" / "provenance.json").read_text(encoding="utf-8")) == seed


def test_reapplying_the_same_release_refreshes_rather_than_grows(state):
    """A 6-hourly idempotent loop must not append an entry per cycle.

    The history records RELEASES, not convergence cycles. Without this the file
    grows ~4 entries/day per app forever and `nuk rollback --to` indices shift
    under the operator between one look and the next.
    """
    for _ in range(5):
        nuk.write_provenance(
            "hello", repo="r", branch="main", commit="a" * 40, image_digest="sha256:1"
        )
    history = nuk.read_provenance_history("hello")
    assert len(history) == 1


def test_history_is_capped_at_twenty(state):
    """Spec §8: retention is the last 20 entries."""
    for i in range(25):
        nuk.write_provenance(
            "hello", repo="r", branch="main", commit=f"{i:040d}", image_digest=None
        )
    history = nuk.read_provenance_history("hello")
    assert len(history) == 20
    assert history[-1].commit == f"{24:040d}"
    assert history[0].commit == f"{5:040d}"


def test_malformed_lines_are_skipped(state):
    """A half-written line from a killed apply must not blank the history."""
    releases, _ = state
    releases.mkdir()
    (releases / "hello.jsonl").write_text(
        json.dumps({"commit": "a" * 40})
        + "\n{not json\n"
        + json.dumps({"commit": "b" * 40})
        + "\n",
        encoding="utf-8",
    )
    assert [e.commit for e in nuk.read_provenance_history("hello")] == ["a" * 40, "b" * 40]


def test_an_absent_history_reads_as_empty(state):
    assert nuk.read_provenance_history("hello") == []
    assert nuk.read_provenance("hello") is None


# --- rollback -----------------------------------------------------------------


def _entry(commit, digest, i):
    return {
        "repo": "r",
        "branch": "main",
        "commit": commit,
        "imageDigest": digest,
        "appliedAt": f"2026-01-0{i}T00:00:00.000Z",
    }


def _history(releases, deploys, name, entries):
    """Seed name's release history (JSONL) and a VALID persisted manifest.

    The manifest must validate under the current schema: cmd_rollback's schema
    gate is under test in its own test below, and every other test needs a
    manifest that PASSES it.
    """
    releases.mkdir(exist_ok=True)
    (releases / f"{name}.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8"
    )
    (deploys / name).mkdir(exist_ok=True)
    (deploys / name / "manifest.yml").write_text(
        "apiVersion: nuk/v1\nkind: Deployment\nmetadata: {name: hello}\n",
        encoding="utf-8",
    )


def test_rollback_reapplies_the_previous_release_by_digest(state, monkeypatch):
    """Spec §8: the digest is the identity; the commit pins the compose tree."""
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [
            _entry("a" * 40, "sha256:1", 1),
            _entry("b" * 40, "sha256:2", 2),
        ],
    )
    seen = {}

    def fake_apply(path, repo_path, *, pin_commit=None, pin_digest=None):
        seen.update(path=path, pin_commit=pin_commit, pin_digest=pin_digest)

    monkeypatch.setattr(nuk, "cmd_apply", fake_apply)
    nuk.cmd_rollback("hello", to=None, show=False)
    assert seen["pin_commit"] == "a" * 40
    assert seen["pin_digest"] == "sha256:1"
    assert seen["path"] == deploys / "hello" / "manifest.yml"


def test_rollback_to_an_explicit_index(state, monkeypatch):
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [
            _entry("a" * 40, "sha256:1", 1),
            _entry("b" * 40, "sha256:2", 2),
            _entry("c" * 40, "sha256:3", 3),
        ],
    )
    seen = {}
    monkeypatch.setattr(
        nuk,
        "cmd_apply",
        lambda path, repo_path, *, pin_commit=None, pin_digest=None: seen.update(
            pin_commit=pin_commit, pin_digest=pin_digest
        ),
    )
    nuk.cmd_rollback("hello", to=0, show=False)
    assert seen["pin_commit"] == "a" * 40
    assert seen["pin_digest"] == "sha256:1"


def test_rollback_refuses_without_a_previous_release(state, monkeypatch):
    releases, deploys = state
    _history(releases, deploys, "hello", [_entry("a" * 40, "sha256:1", 1)])
    monkeypatch.setattr(
        nuk,
        "cmd_apply",
        lambda *a, **k: pytest.fail("must not apply with no previous release"),
    )
    with pytest.raises(SystemExit, match="no previous release"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_refuses_an_out_of_range_index(state, monkeypatch):
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match="no release at index 7"):
        nuk.cmd_rollback("hello", to=7, show=False)


def test_rollback_refuses_an_entry_with_no_digest(state, monkeypatch):
    """Spec §8: the digest is the identity — an entry without one is not re-appliable."""
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [
            _entry("a" * 40, None, 1),
            _entry("b" * 40, "sha256:2", 2),
        ],
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match="no recorded imageDigest"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_refuses_an_entry_with_no_commit(state, monkeypatch):
    """A workflow deploy from a .git-less tree records commit=None — the compose
    tree is unreproducible, so the release is not re-appliable.
    """
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [
            _entry(None, "sha256:1", 1),
            _entry("b" * 40, "sha256:2", 2),
        ],
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match="no recorded commit"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_refuses_when_the_manifest_is_gone(state, monkeypatch):
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )
    (deploys / "hello" / "manifest.yml").unlink()
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match=r"manifest\.yml"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_refuses_when_the_manifest_no_longer_validates(state, monkeypatch):
    """Spec §8: schema refusal — never silently upgrade an entry into a new schema."""
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )

    class OldSchema:
        def validate_python(self, raw):
            title = "Manifest"
            raise pydantic.ValidationError.from_exception_data(title, [])

    monkeypatch.setattr(nuk, "_MANIFEST_ADAPTER", OldSchema())
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match="no longer validates"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_refuses_a_persisted_facility(state, monkeypatch):
    """Facility rollback is the tag, not this command (spec §8)."""
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )
    (deploys / "hello" / "manifest.yml").write_text(
        "apiVersion: nuk/v1\nkind: Facility\nmetadata: {name: hello}\n", encoding="utf-8"
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    with pytest.raises(SystemExit, match="Facility, not a Deployment"):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_failure_leaves_current_state_running(state, monkeypatch):
    """Spec §8: a failed re-apply (digest gone at pull time) aborts cleanly.

    The pull failure propagates out of cmd_rollback — nothing was written or
    recreated before it, so the current stack keeps running.
    """
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )
    monkeypatch.setattr(
        nuk,
        "cmd_apply",
        lambda *a, **k: (_ for _ in ()).throw(subprocess.CalledProcessError(1, ["docker", "pull"])),
    )
    with pytest.raises(subprocess.CalledProcessError):
        nuk.cmd_rollback("hello", to=None, show=False)


def test_rollback_list_prints_indices_digests_and_applies_nothing(state, monkeypatch, capsys):
    releases, deploys = state
    _history(
        releases,
        deploys,
        "hello",
        [_entry("a" * 40, "sha256:1", 1), _entry("b" * 40, "sha256:2", 2)],
    )
    monkeypatch.setattr(nuk, "cmd_apply", lambda *a, **k: pytest.fail("must not apply"))
    nuk.cmd_rollback("hello", to=None, show=True)
    out = capsys.readouterr().out
    assert "0" in out
    assert "sha256:1" in out
    assert "a" * 12 in out
    assert "current" in out


def test_pin_image_pulls_and_retags_the_matching_compose_ref(monkeypatch):
    commands = []
    monkeypatch.setattr(
        nuk,
        "_compose_images",
        lambda name, raw: ["ghcr.io/astrojones/hello:main", "ghcr.io/astrojones/hello:sidecar"],
    )
    monkeypatch.setattr(nuk, "sh", lambda *cmd: commands.append(cmd))
    nuk._pin_image("hello", {"spec": {}}, "ghcr.io/astrojones/hello@sha256:abc")
    assert ("docker", "pull", "ghcr.io/astrojones/hello@sha256:abc") in commands
    assert (
        "docker",
        "tag",
        "ghcr.io/astrojones/hello@sha256:abc",
        "ghcr.io/astrojones/hello:main",
    ) in commands
    assert (
        "docker",
        "tag",
        "ghcr.io/astrojones/hello@sha256:abc",
        "ghcr.io/astrojones/hello:sidecar",
    ) in commands


def test_pin_image_refuses_when_no_compose_ref_matches(monkeypatch):
    monkeypatch.setattr(nuk, "_compose_images", lambda name, raw: ["quay.io/other/app:main"])
    monkeypatch.setattr(nuk, "sh", lambda *cmd: pytest.fail("must not pull"))
    with pytest.raises(SystemExit, match="references no image"):
        nuk._pin_image("hello", {"spec": {}}, "ghcr.io/astrojones/hello@sha256:abc")


def test_pin_image_fails_closed_when_the_digest_is_gone(monkeypatch):
    """Spec §8: pull fails (digest GC'd / unreachable) -> abort BEFORE any retag."""
    pulled = []

    def sh(*cmd):
        if cmd[:2] == ("docker", "pull"):
            pulled.append(cmd)
            raise subprocess.CalledProcessError(1, cmd)
        pytest.fail("must not retag a digest that could not be pulled")

    monkeypatch.setattr(nuk, "_compose_images", lambda name, raw: ["ghcr.io/astrojones/hello:main"])
    monkeypatch.setattr(nuk, "sh", sh)
    with pytest.raises(subprocess.CalledProcessError):
        nuk._pin_image("hello", {"spec": {}}, "ghcr.io/astrojones/hello@sha256:abc")
    assert len(pulled) == 1
