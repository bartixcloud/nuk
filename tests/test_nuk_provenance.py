"""Provenance is a history, not a record (spec §8).

Pure filesystem + JSON — no docker, no network, no /opt/nuklaut. RELEASES and
DEPLOYS are monkeypatched to tmp_path, the same isolation pattern
test_nuk_status.py uses.
"""

from __future__ import annotations

import json
import subprocess

import pydantic
import pytest

import nuk


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
    assert [e["commit"] for e in history] == ["a" * 40, "b" * 40]


def test_read_provenance_returns_the_newest_entry(state):
    """The single-dict contract cmd_status and _overview_provenance depend on."""
    nuk.write_provenance("hello", repo="r", branch="main", commit="a" * 40, image_digest=None)
    nuk.write_provenance("hello", repo="r", branch="main", commit="b" * 40, image_digest=None)
    current = nuk.read_provenance("hello")
    assert current is not None
    assert current["commit"] == "b" * 40


def test_a_legacy_single_object_seeds_a_one_entry_history(state):
    """Files written by nuk <= 0.18 at DEPLOYS/<name>/provenance.json are a bare object."""
    _, deploys = state
    (deploys / "hello").mkdir()
    (deploys / "hello" / "provenance.json").write_text(
        json.dumps({"repo": "r", "branch": "main", "commit": "a" * 40,
                    "imageDigest": None, "appliedAt": "2026-01-01T00:00:00.000Z"}),
        encoding="utf-8",
    )
    history = nuk.read_provenance_history("hello")
    assert len(history) == 1
    assert history[0]["commit"] == "a" * 40


def test_a_legacy_list_seeds_the_history(state):
    """The interim 0.19 format at the same path was a JSON array."""
    _, deploys = state
    (deploys / "hello").mkdir()
    (deploys / "hello" / "provenance.json").write_text(
        json.dumps([
            {"repo": "r", "branch": "main", "commit": c,
             "imageDigest": None, "appliedAt": "2026-01-01T00:00:00.000Z"}
            for c in ("a" * 40, "b" * 40)
        ]),
        encoding="utf-8",
    )
    assert [e["commit"] for e in nuk.read_provenance_history("hello")] == ["a" * 40, "b" * 40]


def test_appending_to_a_legacy_seed_writes_jsonl_and_leaves_the_seed_untouched(state):
    releases, deploys = state
    (deploys / "hello").mkdir()
    seed = {"repo": "r", "branch": "main", "commit": "a" * 40,
            "imageDigest": None, "appliedAt": "2026-01-01T00:00:00.000Z"}
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
    assert history[-1]["commit"] == f"{24:040d}"
    assert history[0]["commit"] == f"{5:040d}"


def test_malformed_lines_are_skipped(state):
    """A half-written line from a killed apply must not blank the history."""
    releases, _ = state
    releases.mkdir()
    (releases / "hello.jsonl").write_text(
        json.dumps({"commit": "a" * 40}) + "\n{not json\n" + json.dumps({"commit": "b" * 40}) + "\n",
        encoding="utf-8",
    )
    assert [e["commit"] for e in nuk.read_provenance_history("hello")] == ["a" * 40, "b" * 40]


def test_an_absent_history_reads_as_empty(state):
    assert nuk.read_provenance_history("hello") == []
    assert nuk.read_provenance("hello") is None
