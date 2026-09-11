"""The effects contract — vocabulary from git, and every fail-closed path.

Spec: docs/superpowers/specs/2026-08-15-astrocloud-platform-design.md §5.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import nuk

OAUTH_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: auth}
    spec:
      placement: {role: edge}
      provides:
        route:
          capability: auth
          middlewares: [oauth-errors@file, oauth-auth@file]
      health: {containers: [authentik-server]}
"""

BASIC_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: basic-auth}
    spec:
      placement: {role: edge}
      provides:
        route: {capability: basic, middlewares: [auth@file]}
"""

TLS_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: ingress}
    spec:
      placement: {role: edge}
      compose: files/docker-compose.traefik.yml
      provides:
        route: {capability: tls}
      health: {containers: [traefik]}
"""

DATA_FACILITY = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: data-stack}
    spec:
      placement: {role: data}
      compose: files/docker-compose.data.yml
      provides:
        env: {capability: databases, bind: postgres}
      health: {containers: [nuk-postgres, nuk-redis]}
"""


def _tree(tmp_path: Path, **facilities: str) -> Path:
    """Build a manifest tree with <tree>/facilities/<name>.yml for each kwarg."""
    fdir = tmp_path / "facilities"
    fdir.mkdir(parents=True, exist_ok=True)
    for name, body in facilities.items():
        (fdir / f"{name}.yml").write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return tmp_path


def test_load_facilities_reads_every_manifest(tmp_path):
    tree = _tree(tmp_path, oauth=OAUTH_FACILITY, data=DATA_FACILITY)
    names = sorted(f.metadata.name for f in nuk.load_facilities(tree))
    assert names == ["auth", "data-stack"]


def test_load_facilities_on_a_tree_with_no_facility_dir(tmp_path):
    assert nuk.load_facilities(tmp_path) == []


def test_load_facilities_ignores_deployments_in_the_dir(tmp_path):
    tree = _tree(tmp_path, oauth=OAUTH_FACILITY)
    (tree / "facilities" / "stray.yml").write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Deployment
            metadata: {name: stray}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    assert [f.metadata.name for f in nuk.load_facilities(tree)] == ["auth"]


def test_route_vocabulary_maps_capability_to_middlewares(tmp_path):
    tree = _tree(tmp_path, oauth=OAUTH_FACILITY, basic=BASIC_FACILITY, tls=TLS_FACILITY)
    vocab = nuk.route_vocabulary(nuk.load_facilities(tree))
    assert vocab == {
        "auth": ["oauth-errors@file", "oauth-auth@file"],
        "basic": ["auth@file"],
        "tls": [],
    }


def test_route_vocabulary_refuses_a_duplicate_capability(tmp_path):
    """A closed vocabulary with two answers is not closed. Refuse."""
    tree = _tree(tmp_path, oauth=OAUTH_FACILITY)
    (tree / "facilities" / "shadow.yml").write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Facility
            metadata: {name: shadow}
            spec:
              provides:
                route: {capability: auth, middlewares: [evil@file]}
            """
        ).lstrip(),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        nuk.route_vocabulary(nuk.load_facilities(tree))


def test_env_facility_finds_the_declaring_facility(tmp_path):
    tree = _tree(tmp_path, data=DATA_FACILITY, oauth=OAUTH_FACILITY)
    f = nuk.env_facility(nuk.load_facilities(tree), "databases")
    assert f is not None
    assert f.metadata.name == "data-stack"


def test_env_facility_returns_none_when_undeclared(tmp_path):
    tree = _tree(tmp_path, oauth=OAUTH_FACILITY)
    assert nuk.env_facility(nuk.load_facilities(tree), "databases") is None


# --- the static consumption map (spec §5.3) ------------------------------------------


def _dep(spec: dict) -> nuk.Deployment:
    """A minimal valid Deployment carrying `spec`."""
    return nuk.Deployment.model_validate(
        {"apiVersion": "nuk/v1", "kind": "Deployment", "metadata": {"name": "x"}, "spec": spec}
    )


def test_consumes_maps_oauth_ingress_to_the_auth_capability():
    dep = _dep(
        {"ingress": [{"host": "h.example.com", "service": "web", "port": 80, "auth": "oauth"}]}
    )
    assert nuk.consumes(dep) == {"auth"}


def test_consumes_maps_databases_to_the_databases_capability():
    assert nuk.consumes(_dep({"databases": {"postgres": True}})) == {"databases"}
    assert nuk.consumes(_dep({"databases": {"redis": True}})) == {"databases"}


def test_consumes_combines_route_and_env():
    dep = _dep(
        {
            "ingress": [{"host": "h.example.com", "service": "web", "port": 80, "auth": "oauth"}],
            "databases": {"postgres": True},
        }
    )
    assert nuk.consumes(dep) == {"auth", "databases"}


def test_a_deployment_consuming_nothing_gets_an_empty_set():
    """It still gets the default tls route from the ingress facility — tls is
    substrate, never consumption (spec §5.3).
    """
    dep = _dep({"ingress": [{"host": "h.example.com", "service": "web", "port": 80}]})
    assert nuk.consumes(dep) == set()
