"""A Deployment without spec.source.repo reads its compose payload from the tree.

Spec: docs/superpowers/specs/2026-10-04-platform-design.md §3.1 — a Deployment's
compose payload comes from `spec.source.repo` *or* sourceless from
`<tree>/deployments/<name>/`, exactly like a sourceless Facility. A tenant source
therefore ships a few lines of compose instead of making the app host clone (and
hold a credential for) an app repo.

    uv run pytest tests/test_nuk_payload.py
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import nuk

SOURCELESS = """\
apiVersion: nuk/v1
kind: Deployment
metadata: {name: hello}
spec:
  placement: {role: app}
  compose: docker-compose.yml
"""

OWN_REPO = "git@github.com:astrojones/infra.git"


@pytest.fixture
def applied(tmp_path, monkeypatch):
    """Stub everything cmd_apply touches outside the manifest; `commands` records sh()."""
    commands: list[tuple[str, ...]] = []

    def fake_sh(*cmd):
        commands.append(cmd)

    monkeypatch.setattr(nuk, "sh", fake_sh)
    monkeypatch.setattr(nuk.paths, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk.paths, "DEPLOYS", tmp_path / "deployments")
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["docker", "compose"])
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    return commands


def _with_source(body: str, repo: str) -> str:
    """The same manifest, naming `repo` as its payload repo in `spec.source.repo`."""
    return body.replace(
        "  compose: docker-compose.yml\n",
        f"  compose: docker-compose.yml\n  source: {{repo: '{repo}'}}\n",
    )


def _tree(tmp_path: Path, *, payload: bool = True, body: str = SOURCELESS) -> Path:
    """`<tree>/deployments/hello.yml`, with its payload dir unless `payload` is false."""
    tree = tmp_path / "tree"
    (tree / "deployments").mkdir(parents=True)
    manifest = tree / "deployments" / "hello.yml"
    manifest.write_text(textwrap.dedent(body), encoding="utf-8")
    if payload:
        payload_dir = tree / "deployments" / "hello"
        payload_dir.mkdir()
        (payload_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return manifest


def _ctx(
    manifest: Path, *, tenant: str | None = None, source_repo: str | None = None
) -> nuk.TreeContext:
    return nuk.TreeContext.build(
        manifest.parent.parent,
        "app",
        "10.0.11.10",
        tenant,
        nuk.APPLY_ALL,
        source_repo=source_repo,
    )


def test_a_sourceless_deployment_mirrors_its_payload(tmp_path, applied):
    """compose_args' existing `-f repo/<file>` resolution must work without a clone."""
    manifest = _tree(tmp_path)

    nuk.cmd_apply(manifest, None, ctx=_ctx(manifest))

    rsync = [c for c in applied if c[0] == "rsync"]
    assert len(rsync) == 1
    assert rsync[0][-2].rstrip("/").endswith("deployments/hello")
    assert rsync[0][-1].rstrip("/").endswith("deployments/hello/repo")
    assert [c[:2] for c in applied if c[0] == "git"] == []


def test_the_payload_is_converged_in_place_never_recreated(tmp_path, applied):
    """Removing repo/ first hands running containers a new inode under their bind mounts."""
    manifest = _tree(tmp_path)
    repo = tmp_path / "deployments" / "hello" / "repo"
    repo.mkdir(parents=True)
    before = repo.stat().st_ino

    nuk.cmd_apply(manifest, None, ctx=_ctx(manifest))

    assert repo.stat().st_ino == before
    assert "--delete" in next(c for c in applied if c[0] == "rsync")


def test_a_sourceless_deployment_without_a_payload_refuses(tmp_path, applied):
    manifest = _tree(tmp_path, payload=False)

    with pytest.raises(SystemExit, match=r"deployments/hello/ payload directory"):
        nuk.cmd_apply(manifest, None, ctx=_ctx(manifest))


def test_a_tenant_source_may_not_name_a_repo_other_than_its_own(tmp_path, applied):
    """The tree is the review unit: a tenant must not make the app host clone a foreign repo.

    Found on `deploy` 2026-10-16: `astrojones/infra` named `astrojones/pd-site`, so the
    app host cloned an app repo as root with ambient credentials — and then pinned that
    clone to the infra tag's commit, which cannot work.
    """
    manifest = _tree(tmp_path, body=_with_source(SOURCELESS, "https://github.com/astrojones/hello.git"))

    with pytest.raises(SystemExit, match="is not allowed"):
        nuk.cmd_apply(manifest, None, ctx=_ctx(manifest, tenant="astrojones", source_repo=OWN_REPO))

    assert [c[:2] for c in applied if c[0] == "git"] == []


def test_a_tenant_source_may_name_its_own_repo(tmp_path, applied):
    """`kolbeapp-de` ships the payload in the tenant's own repo — that clone stays legal."""
    manifest = _tree(
        tmp_path,
        body=_with_source(SOURCELESS, "https://github.com/astrojones/infra.git"),
        payload=False,
    )

    nuk.cmd_apply(manifest, None, ctx=_ctx(manifest, tenant="astrojones", source_repo=OWN_REPO))

    assert next(c[:2] for c in applied if c[0] == "git") == ("git", "clone")


def test_the_platform_source_may_name_any_repo(tmp_path, applied):
    """`ctx.tenant is None` for the platform source: that tree is the platform owner's own."""
    manifest = _tree(
        tmp_path,
        body=_with_source(SOURCELESS, "https://github.com/astrojones/hello.git"),
        payload=False,
    )

    nuk.cmd_apply(manifest, None, ctx=_ctx(manifest, source_repo=OWN_REPO))

    assert next(c[:2] for c in applied if c[0] == "git") == ("git", "clone")


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("git@github.com:o/r.git", "https://github.com/o/r.git"),
        ("ssh://git@github.com/o/r.git", "git@github.com:o/r"),
        ("git@GitHub.com:o/r.git", "https://github.COM/o/r/"),
    ],
)
def test_same_repo_ignores_transport_form(left, right):
    assert nuk._same_repo(left, right)


@pytest.mark.parametrize("right", ["git@github.com:o/other.git", "git@github.com:o", None])
def test_same_repo_refuses_a_different_repo(right):
    assert not nuk._same_repo("git@github.com:o/r.git", right)
