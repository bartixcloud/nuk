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


def test_placement_parses_optional_host(tmp_path):
    m = nuk.load(
        _write(
            tmp_path,
            """
            apiVersion: nuk/v1
            kind: Deployment
            metadata: {name: pinned}
            spec:
              source: {repo: https://github.com/bartixcloud/x.git}
              placement: {role: app, host: kolbe-app}
            """,
        )
    )
    assert m.spec.placement.host == "kolbe-app"


def test_placement_host_defaults_to_none(tmp_path):
    m = nuk.load(_write(tmp_path, DEPLOYMENT_HELLO))
    assert m.spec.placement.host is None


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


def test_facility_apply_refuses_when_unprivileged(tmp_path, monkeypatch, capsys):
    """Spec §4.4/§12: non-privileged `nuk apply <Facility>` raises."""
    doc = _write(tmp_path, FACILITY_AUTH)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: False)
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    with pytest.raises(SystemExit):
        nuk.cmd_apply(doc, None)
    captured = capsys.readouterr()  # ONE call — a second returns empty
    assert "nuk-facility" in captured.out + captured.err


def test_deployment_apply_is_not_gated_by_privilege(tmp_path, monkeypatch):
    """Only Facilities need authority. A Deployment must not trip the guard.

    Stop right after the guard by making placement mismatch, so the test asserts
    on the guard alone and never reaches git or docker.
    """
    doc = _write(tmp_path, DEPLOYMENT_HELLO)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: False)
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    nuk.cmd_apply(doc, None)  # placement app != edge -> clean no-op, no SystemExit


def test_is_privileged_true_for_root(monkeypatch):
    monkeypatch.setattr(nuk.os, "geteuid", lambda: 0)
    assert nuk._is_privileged() is True


def test_is_privileged_false_without_group(monkeypatch):
    monkeypatch.setattr(nuk.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(nuk.os, "getgroups", lambda: [1000])
    monkeypatch.setattr(nuk.grp, "getgrnam", _raise_keyerror)
    assert nuk._is_privileged() is False


def test_is_privileged_true_via_group(monkeypatch):
    class _Grp:
        gr_gid = 4242

    monkeypatch.setattr(nuk.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(nuk.os, "getgroups", lambda: [1000, 4242])
    monkeypatch.setattr(nuk.grp, "getgrnam", lambda _name: _Grp())
    assert nuk._is_privileged() is True


def _raise_keyerror(_name):
    raise KeyError(_name)


def test_sourceless_facility_mirrors_its_payload(tmp_path, monkeypatch):
    """A Facility with no source.repo applies its <tree>/facilities/<name>/ payload."""
    tree = tmp_path / "tree"
    (tree / "facilities" / "data-stack").mkdir(parents=True)
    (tree / "facilities" / "data-stack" / "docker-compose.data.yml").write_text(
        "services: {}\n", encoding="utf-8"
    )
    manifest = tree / "facilities" / "data-stack.yml"
    manifest.write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Facility
            metadata: {name: data-stack}
            spec:
              placement: {role: data}
              compose: docker-compose.data.yml
            """
        ).lstrip(),
        encoding="utf-8",
    )
    commands = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd: commands.append(cmd))
    monkeypatch.setattr(nuk, "read_self", lambda: ("data", "10.0.10.180"))
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deployments")
    monkeypatch.setattr(nuk, "provision_databases", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "resolve_db_services", lambda *_a: [])
    monkeypatch.setattr(nuk, "resolve_env_from", lambda _s: [])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "write_ingress", lambda *_a: None)
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["docker", "compose"])
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    nuk.cmd_apply(manifest, None)
    rsync = [c for c in commands if c[0] == "rsync"]
    assert len(rsync) == 1
    src = rsync[0][-2].rstrip("/")
    assert src.endswith("facilities/data-stack")


def test_sourceless_facility_without_payload_refuses(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    (tree / "facilities").mkdir(parents=True)
    manifest = tree / "facilities" / "data-stack.yml"
    manifest.write_text(
        textwrap.dedent(
            """
            apiVersion: nuk/v1
            kind: Facility
            metadata: {name: data-stack}
            spec:
              placement: {role: data}
              compose: docker-compose.data.yml
            """
        ).lstrip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(nuk, "read_self", lambda: ("data", "10.0.10.180"))
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deployments")
    with pytest.raises(SystemExit, match="payload directory"):
        nuk.cmd_apply(manifest, None)


def test_declaration_only_facility_without_spec_applies(tmp_path, monkeypatch):
    """A Facility with no `spec:` at all is valid; cmd_apply must not KeyError on raw["spec"]."""
    doc = tmp_path / "decl.yml"
    doc.write_text("apiVersion: nuk/v1\nkind: Facility\nmetadata: {name: decl}\n", encoding="utf-8")
    monkeypatch.setattr(nuk, "read_self", lambda: ("edge", "10.0.10.241"))
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "DYNAMIC", tmp_path / "dynamic")
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "deployments")
    monkeypatch.setattr(nuk, "load_facilities", lambda _t, **_k: [])
    monkeypatch.setattr(nuk, "load_org", lambda _p: object())
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda *_a, **_k: None)
    nuk.cmd_apply(doc, None)  # must not raise


def test_is_privileged_false_when_nss_is_broken(monkeypatch):
    monkeypatch.setattr(nuk.os, "geteuid", lambda: 1000)

    def boom(_name):
        msg = "NSS unavailable"
        raise OSError(msg)

    monkeypatch.setattr(nuk.grp, "getgrnam", boom)
    assert nuk._is_privileged() is False
