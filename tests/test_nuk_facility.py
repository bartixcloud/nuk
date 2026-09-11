"""kind: Facility — the discriminated union, placement, and the authority guard.

Spec: docs/superpowers/specs/2026-08-15-astrocloud-platform-design.md §4.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import nuk


def _write(tmp_path: Path, body: str, name: str = "m.yml") -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


FACILITY_AUTH = """
    apiVersion: nuk/v1
    kind: Facility
    metadata: {name: auth}
    spec:
      placement: {role: edge}
      source: {repo: https://github.com/astrojones/authentik.git}
      provides:
        route:
          capability: auth
          middlewares: [oauth-errors@file, oauth-auth@file]
      health: {containers: [authentik-server]}
"""

DEPLOYMENT_HELLO = """
    apiVersion: nuk/v1
    kind: Deployment
    metadata: {name: hello}
    spec:
      placement: {role: app}
      source: {repo: https://github.com/astrojones/hello.git, branch: kapitel-1}
      ingress:
        - {host: hello.bitcoinalchemist.com, service: web, port: 8080}
"""


def test_load_returns_facility_for_kind_facility(tmp_path):
    m = nuk.load(_write(tmp_path, FACILITY_AUTH))
    assert isinstance(m, nuk.Facility)
    assert m.kind == "Facility"
    assert m.spec.placement.role == "edge"
    assert m.spec.provides.route.capability == "auth"
    assert m.spec.provides.route.middlewares == ["oauth-errors@file", "oauth-auth@file"]
    assert m.spec.health.containers == ["authentik-server"]


def test_load_returns_deployment_for_kind_deployment(tmp_path):
    m = nuk.load(_write(tmp_path, DEPLOYMENT_HELLO))
    assert isinstance(m, nuk.Deployment)
    assert m.spec.placement.role == "app"
    assert m.spec.ingress[0].host == "hello.bitcoinalchemist.com"


def test_facility_carries_env_provide(tmp_path):
    m = nuk.load(
        _write(
            tmp_path,
            """
            apiVersion: nuk/v1
            kind: Facility
            metadata: {name: data-stack}
            spec:
              placement: {role: data}
              compose: files/docker-compose.data.yml
              provides:
                env: {capability: databases, bind: postgres}
              health: {containers: [nuk-postgres, nuk-redis]}
            """,
        )
    )
    assert m.spec.provides.env.capability == "databases"
    assert m.spec.provides.env.bind == "postgres"
    assert m.spec.provides.route is None


def test_unknown_kind_is_rejected(tmp_path):
    """Spec §12: an unknown `kind` is rejected — the union is closed."""
    doc = _write(
        tmp_path,
        """
        apiVersion: nuk/v1
        kind: StatefulSet
        metadata: {name: nope}
        """,
    )
    with pytest.raises(SystemExit):
        nuk.load(doc)


def test_placement_is_optional_on_a_legacy_deployment(tmp_path):
    """Manifests written before placement existed must still load, unplaced."""
    m = nuk.load(
        _write(
            tmp_path,
            """
            apiVersion: nuk/v1
            kind: Deployment
            metadata: {name: legacy}
            spec:
              source: {repo: https://github.com/astrojones/legacy.git}
            """,
        )
    )
    assert m.spec.placement is None


def test_unknown_placement_role_is_rejected(tmp_path):
    doc = _write(
        tmp_path,
        """
        apiVersion: nuk/v1
        kind: Deployment
        metadata: {name: bad}
        spec:
          placement: {role: worker}
        """,
    )
    with pytest.raises(SystemExit):
        nuk.load(doc)


def test_placement_matches_own_role(tmp_path):
    m = nuk.load(_write(tmp_path, DEPLOYMENT_HELLO))
    assert nuk.placement_matches(m, "app") is True


def test_placement_does_not_match_other_role(tmp_path):
    m = nuk.load(_write(tmp_path, DEPLOYMENT_HELLO))
    assert nuk.placement_matches(m, "edge") is False


def test_unplaced_manifest_matches_every_role(tmp_path):
    """No placement = legacy manifest. It applies wherever it is run, as before."""
    m = nuk.load(
        _write(
            tmp_path,
            """
            apiVersion: nuk/v1
            kind: Deployment
            metadata: {name: legacy}
            spec:
              source: {repo: https://github.com/astrojones/legacy.git}
            """,
        )
    )
    assert nuk.placement_matches(m, "app") is True
    assert nuk.placement_matches(m, "edge") is True


def test_all_in_one_matches_every_placement(tmp_path):
    """all-in-one is a real composition of edge + data + app (spec §3.1)."""
    m = nuk.load(_write(tmp_path, DEPLOYMENT_HELLO))
    assert nuk.placement_matches(m, "all-in-one") is True
    f = nuk.load(_write(tmp_path, FACILITY_AUTH, name="f.yml"))
    assert nuk.placement_matches(f, "all-in-one") is True
