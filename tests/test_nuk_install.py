"""`spec.install`: a facility installs files from the verified tag into traefik/dynamic/.

The rendering is structure-aware (tokens only in YAML values) and the write is atomic,
because Traefik watches the directory and a truncate is visible as an empty file.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import textwrap
from pathlib import Path

import nuk
import pytest
import yaml
from nuk import install
from pydantic import ValidationError

GLOBAL = """\
# __DOMAIN__ in a comment must survive nothing: comments are not part of the render.
http:
  routers:
    dash:
      rule: "Host(`traefik.__DOMAIN__`)"
  services:
    backend:
      loadBalancer:
        servers:
          - url: "http://__AUTH_BACKEND__"
  middlewares:
    auth:
      basicAuth:
        users:
          - "__DASHBOARD_AUTH__"
"""

ORG = """\
apiVersion: nukorg/v1
kind: Org
metadata: {name: akd}
domains: [example.com]
platformDomain: example.com
acmeEmail: admin@example.com
hosts:
  - {name: akd, provider: manual, role: all-in-one}
facilities: {dns: manual, tls: http01, secrets: sops, runners: none}
"""

FACILITY = """\
apiVersion: nuk/v1
kind: Facility
metadata: {name: ingress}
spec:
  placement: {role: edge}
  compose: docker-compose.yml
  install:
    - src: global.yml
      name: global.yml
      vars: {AUTH_BACKEND: "authentik-server:9000"}
      secretVars: {DASHBOARD_AUTH: SECRETS/dashboard-users}
"""


# --- the model ----------------------------------------------------------------------------


def _item(**over):
    return nuk.Install.model_validate({"src": "global.yml", "name": "global.yml", **over})


@pytest.mark.parametrize("src", ["../x.yml", "/etc/passwd", "a/../../b.yml"])
def test_install_src_must_stay_inside_the_payload(src):
    with pytest.raises(ValidationError):
        _item(src=src)


@pytest.mark.parametrize("name", ["sub/global.yml", "../global.yml", "global.txt", ".global.yml"])
def test_install_name_is_a_plain_yaml_filename(name):
    with pytest.raises(ValidationError):
        _item(name=name)


def test_a_facility_without_install_has_none():
    doc = yaml.safe_load("apiVersion: nuk/v1\nkind: Facility\nmetadata: {name: x}\n")
    assert nuk.Facility.model_validate(doc).spec.install == []


# --- structure-aware rendering ------------------------------------------------------------


def test_tokens_are_replaced_in_values_only():
    tokens = {"DOMAIN": "a.net", "AUTH_BACKEND": "x:1", "DASHBOARD_AUTH": "u:h"}
    out = install.render(GLOBAL, tokens)
    doc = yaml.safe_load(out)
    assert doc["http"]["routers"]["dash"]["rule"] == "Host(`traefik.a.net`)"
    assert doc["http"]["services"]["backend"]["loadBalancer"]["servers"] == [{"url": "http://x:1"}]
    assert doc["http"]["middlewares"]["auth"]["basicAuth"]["users"] == ["u:h"]


def test_a_value_that_would_break_yaml_stays_data():
    """The 2026-07-21 failure: a multi-line value cut through the structure. Not here."""
    nasty = "u:$apr1$x\n  injected: true\n# comment"
    out = install.render(GLOBAL, {"DOMAIN": "a", "AUTH_BACKEND": "b", "DASHBOARD_AUTH": nasty})
    doc = yaml.safe_load(out)
    assert doc["http"]["middlewares"]["auth"]["basicAuth"]["users"] == [nasty]
    assert "injected" not in doc["http"]["middlewares"]["auth"]


def test_a_token_in_a_key_is_left_alone():
    out = install.render("a:\n  __DOMAIN__: v\n", {"DOMAIN": "x"})
    assert yaml.safe_load(out) == {"a": {"__DOMAIN__": "v"}}


def test_an_unresolved_token_is_refused_without_naming_values():
    with pytest.raises(ValueError, match="AUTH_BACKEND") as e:
        install.render(GLOBAL, {"DOMAIN": "a", "DASHBOARD_AUTH": "sekret-hash"})
    assert "sekret-hash" not in str(e.value)


def test_a_document_that_is_not_a_mapping_is_refused():
    with pytest.raises(ValueError, match="mapping"):
        install.render("- a\n- b\n", {})


# --- installing: ownership and atomicity --------------------------------------------------


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A host layout under tmp_path: dynamic/, its staging sibling, state and secrets."""
    monkeypatch.setattr(nuk.paths, "DYNAMIC", tmp_path / "traefik" / "dynamic")
    monkeypatch.setattr(nuk.paths, "CONVERGE_STATE", tmp_path / "state")
    monkeypatch.setattr(nuk.paths, "INSTALLED", tmp_path / "state" / "installed")
    monkeypatch.setattr(nuk.paths, "SECRET_FILES", tmp_path / "secrets")
    monkeypatch.setattr(nuk.paths, "RUN_SECRETS", tmp_path / "run-secrets")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "dashboard-users").write_text("\nadmin:$apr1$h\n", encoding="utf-8")
    payload = tmp_path / "payload"
    payload.mkdir()
    (payload / "global.yml").write_text(GLOBAL, encoding="utf-8")
    return tmp_path


def _facility_item(host: Path):
    return nuk.Install.model_validate(
        {
            "src": "global.yml",
            "name": "global.yml",
            "vars": {"AUTH_BACKEND": "authentik-server:9000"},
            "secretVars": {"DASHBOARD_AUTH": str(host / "secrets" / "dashboard-users")},
        }
    )


def _org():
    return nuk.Org.model_validate(yaml.safe_load(ORG))


def _run(host: Path, item=None):
    return install.install_file("ingress", item or _facility_item(host), host / "payload", _org())


def test_install_writes_the_rendered_file(host):
    assert _run(host) is True
    doc = yaml.safe_load((host / "traefik" / "dynamic" / "global.yml").read_text())
    assert doc["http"]["routers"]["dash"]["rule"] == "Host(`traefik.example.com`)"
    assert doc["http"]["middlewares"]["auth"]["basicAuth"]["users"] == ["admin:$apr1$h"]
    assert (host / "traefik" / "dynamic" / "global.yml").stat().st_mode & 0o777 == 0o644


def test_install_leaves_no_staging_file_behind(host):
    _run(host)
    staging = host / "traefik" / ".nuk-staging"
    assert not staging.exists() or list(staging.iterdir()) == []
    assert [p.name for p in (host / "traefik" / "dynamic").iterdir()] == ["global.yml"]


def test_unchanged_content_is_not_rewritten(host):
    _run(host)
    dest = host / "traefik" / "dynamic" / "global.yml"
    before = dest.stat().st_ino, dest.stat().st_mtime_ns
    assert _run(host) is False
    assert (dest.stat().st_ino, dest.stat().st_mtime_ns) == before


def test_a_changed_source_replaces_a_file_nuk_wrote(host):
    _run(host)
    tls13 = "tls: {options: {default: {minVersion: VersionTLS13}}}\n"
    (host / "payload" / "global.yml").write_text(GLOBAL + tls13)
    assert _run(host) is True
    dest = host / "traefik" / "dynamic" / "global.yml"
    default = yaml.safe_load(dest.read_text())["tls"]["options"]["default"]
    assert default["minVersion"] == "VersionTLS13"


def test_a_file_nuk_did_not_write_is_refused_and_kept(host):
    dest = host / "traefik" / "dynamic" / "global.yml"
    dest.parent.mkdir(parents=True)
    dest.write_text("http: {baked: by-cloud-init}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not written by nuk"):
        _run(host)
    assert dest.read_text() == "http: {baked: by-cloud-init}\n"


def test_a_file_edited_by_hand_after_install_is_refused(host):
    _run(host)
    dest = host / "traefik" / "dynamic" / "global.yml"
    dest.write_text("http: {hand: edited}\n", encoding="utf-8")
    (host / "payload" / "global.yml").write_text(GLOBAL + "# changed\nx: 1\n")
    with pytest.raises(ValueError, match="not written by nuk"):
        _run(host)
    assert dest.read_text() == "http: {hand: edited}\n"


def test_an_identical_foreign_file_is_adopted(host):
    """A file that already equals the render is nuk's by content; no human step needed."""
    tokens = {
        "DOMAIN": "example.com",
        "AUTH_BACKEND": "authentik-server:9000",
        "DASHBOARD_AUTH": "admin:$apr1$h",
    }
    rendered = install.render(GLOBAL, tokens)
    dest = host / "traefik" / "dynamic" / "global.yml"
    dest.parent.mkdir(parents=True)
    dest.write_text(rendered, encoding="utf-8")
    assert _run(host) is False
    stamp = host / "state" / "installed" / "ingress--global.yml.sha256"
    assert stamp.read_text().strip() == hashlib.sha256(rendered.encode()).hexdigest()


def test_the_swap_is_one_atomic_replace_from_outside_the_watched_dir(host, monkeypatch):
    _run(host)
    dest = host / "traefik" / "dynamic" / "global.yml"
    (host / "payload" / "global.yml").write_text(GLOBAL + "x: 1\n")
    old = dest.read_text()
    seen = {}
    real = os.replace

    def spy(src, dst):
        seen["dest_before"] = dest.read_text()  # never truncated while the swap is pending
        seen["src_parent"] = os.fspath(src).rsplit("/", 1)[0]
        seen["src_complete"] = yaml.safe_load(Path(src).read_text(encoding="utf-8"))["x"]
        real(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    assert _run(host) is True
    assert seen["dest_before"] == old
    assert seen["src_complete"] == 1
    assert seen["src_parent"] == str(host / "traefik" / ".nuk-staging")


def test_a_failed_swap_keeps_the_old_file_and_cleans_staging(host, monkeypatch):
    _run(host)
    dest = host / "traefik" / "dynamic" / "global.yml"
    old = dest.read_text()
    (host / "payload" / "global.yml").write_text(GLOBAL + "x: 1\n")

    def boom(_s, _d):
        msg = "disk gone"
        raise OSError(msg)

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk gone"):
        _run(host)
    assert dest.read_text() == old
    staging = host / "traefik" / ".nuk-staging"
    assert not staging.exists() or list(staging.iterdir()) == []


def test_a_render_failure_writes_nothing(host):
    item = nuk.Install.model_validate({"src": "global.yml", "name": "global.yml"})
    with pytest.raises(ValueError, match="AUTH_BACKEND"):
        install.install_file("ingress", item, host / "payload", _org())
    assert not (host / "traefik" / "dynamic" / "global.yml").exists()


def test_a_secret_file_outside_the_allowed_roots_is_refused(host):
    stray = host / "elsewhere"
    stray.write_text("top-secret\n", encoding="utf-8")
    item = nuk.Install.model_validate(
        {
            "src": "global.yml",
            "name": "global.yml",
            "vars": {"AUTH_BACKEND": "b"},
            "secretVars": {"DASHBOARD_AUTH": str(stray)},
        }
    )
    with pytest.raises(ValueError, match="secret") as e:
        _run(host, item)
    assert "top-secret" not in str(e.value)


def test_a_source_that_escapes_the_payload_through_a_symlink_is_refused(host):
    (host / "outside.yml").write_text("a: 1\n", encoding="utf-8")
    (host / "payload" / "link.yml").symlink_to(host / "outside.yml")
    item = nuk.Install.model_validate({"src": "link.yml", "name": "g.yml"})
    with pytest.raises(ValueError, match="outside the payload"):
        install.install_file("ingress", item, host / "payload", _org())


def test_domain_needs_an_org(host):
    with pytest.raises(ValueError, match="DOMAIN"):
        install.install_file("ingress", _facility_item(host), host / "payload", None)


# --- wired into cmd_apply -----------------------------------------------------------------


def _rsync_stub(*cmd, **_k):
    """Emulate the payload mirror: `rsync -a --delete SRC/ DST/`."""
    if cmd and cmd[0] == "rsync":
        src, dst = cmd[-2].rstrip("/"), cmd[-1].rstrip("/")
        shutil.copytree(src, dst, dirs_exist_ok=True)


@pytest.fixture
def applied_tree(host, monkeypatch):
    tree = host / "tree"
    (tree / "facilities" / "ingress").mkdir(parents=True)
    manifest = FACILITY.replace("SECRETS", str(host / "secrets"))
    (tree / "facilities" / "ingress.yml").write_text(manifest, encoding="utf-8")
    (tree / "facilities" / "ingress" / "global.yml").write_text(GLOBAL, encoding="utf-8")
    (tree / "facilities" / "ingress" / "docker-compose.yml").write_text("services: {}\n")
    (tree / nuk.DEFAULT_ORG_FILE).write_text(ORG, encoding="utf-8")
    monkeypatch.setattr(nuk.paths, "DEPLOYS", host / "deploys")
    monkeypatch.setattr(nuk, "project_dir", lambda name: host / "proj" / name)
    monkeypatch.setattr(nuk, "sh", _rsync_stub)
    monkeypatch.setattr(nuk, "_is_privileged", lambda: True)
    monkeypatch.setattr(nuk, "read_self", lambda: ("all-in-one", None))
    monkeypatch.setattr(nuk, "persist_manifest", lambda *_a: None)
    monkeypatch.setattr(nuk, "write_provenance", lambda *_a, **_k: None)
    monkeypatch.setattr(nuk, "compose_args", lambda *_a: ["true"])
    monkeypatch.setattr(nuk, "write_override", lambda *_a, **_k: None)
    return tree


def test_cmd_apply_installs_a_facilitys_files_from_its_payload(applied_tree, host):
    nuk.cmd_apply(applied_tree / "facilities" / "ingress.yml", None)
    doc = yaml.safe_load((host / "traefik" / "dynamic" / "global.yml").read_text())
    assert doc["http"]["routers"]["dash"]["rule"] == "Host(`traefik.example.com`)"


def test_cmd_apply_refuses_a_facility_whose_install_fails_and_leaves_the_file(applied_tree, host):
    dest = host / "traefik" / "dynamic" / "global.yml"
    dest.parent.mkdir(parents=True)
    dest.write_text("http: {baked: true}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="not written by nuk"):
        nuk.cmd_apply(applied_tree / "facilities" / "ingress.yml", None)
    assert dest.read_text() == "http: {baked: true}\n"


def test_a_facility_without_install_touches_no_dynamic_file(applied_tree, host):
    manifest = textwrap.dedent(
        """\
        apiVersion: nuk/v1
        kind: Facility
        metadata: {name: ingress}
        spec:
          placement: {role: edge}
          compose: docker-compose.yml
        """
    )
    (applied_tree / "facilities" / "ingress.yml").write_text(manifest, encoding="utf-8")
    nuk.cmd_apply(applied_tree / "facilities" / "ingress.yml", None)
    assert not (host / "traefik" / "dynamic" / "global.yml").exists()
