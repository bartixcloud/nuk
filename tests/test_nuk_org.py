"""Unit tests for the nukorg/v1 org capability manifest + `nuk org` helpers.

Pure pyyaml/pydantic — no /opt/nuklaut, no docker, no controller.

    uv run pytest tests/test_nuk_org.py
"""

from __future__ import annotations

import nuk
import pytest
import yaml

ORG_DOC = {
    "apiVersion": "nukorg/v1",
    "kind": "Org",
    "metadata": {"name": "ekd-akd"},
    "domain": "test.a-kd.net",
    "acmeEmail": "ops@a-kd.net",
    "controller": {"hostname": "akd-controller", "provisioner": "manual", "deployMode": "local"},
    "facilities": {
        "dns": "manual",
        "tls": "http01",
        "secrets": "generate",
        "auth": "authentik",
        "runners": "persistent",
        "data": {"postgres": True, "redis": True},
    },
    "overlays": ["strongswan-vpn"],
    "pins": {"core": "astrojones/nuklaut@v1.5.0", "nuk": "astrojones/nuk@v1.2.0"},
}


def _facilities(**over: object) -> dict:
    """ORG_DOC with a shallow override of the facilities block."""
    return {**ORG_DOC, "facilities": {**ORG_DOC["facilities"], **over}}


# --- schema ------------------------------------------------------------------


def test_org_parses_full_manifest():
    org = nuk.Org.model_validate(ORG_DOC)
    assert org.metadata.name == "ekd-akd"
    assert org.domain == "test.a-kd.net"
    assert org.acme_email == "ops@a-kd.net"
    assert org.controller.provisioner == "manual"
    assert org.controller.deploy_mode == "local"
    assert org.facilities.auth == "authentik"
    assert org.facilities.data.postgres is True


def test_org_rejects_unknown_enum():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(auth="ldap"))


def test_org_rejects_bad_provisioner():
    doc = {**ORG_DOC, "controller": {**ORG_DOC["controller"], "provisioner": "pulumi"}}
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(doc)


def test_org_wildcard_requires_dns01():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(dns="wildcard", tls="http01"))


def test_org_dns01_requires_provider():
    with pytest.raises(nuk.ValidationError):
        nuk.Org.model_validate(_facilities(dns="wildcard", tls="dns01"))


def test_org_dns01_with_provider_ok():
    org = nuk.Org.model_validate(_facilities(dns="wildcard", tls="dns01", dnsProvider="hetzner"))
    assert org.facilities.dns_provider == "hetzner"


# --- loader / accessor -------------------------------------------------------


def test_load_org_roundtrip(tmp_path):
    p = tmp_path / "nuklaut.org.yml"
    p.write_text(yaml.safe_dump(ORG_DOC), encoding="utf-8")
    assert nuk.load_org(p).metadata.name == "ekd-akd"


def test_load_org_invalid_exits(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("apiVersion: nukorg/v1\nkind: Org\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        nuk.load_org(p)


def test_org_get_dotted_by_alias():
    org = nuk.Org.model_validate(ORG_DOC)
    assert nuk.org_get(org, "facilities.auth") == "authentik"
    assert nuk.org_get(org, "controller.deployMode") == "local"
    assert nuk.org_get(org, "metadata.name") == "ekd-akd"


def test_org_get_missing_key_exits():
    org = nuk.Org.model_validate(ORG_DOC)
    with pytest.raises(SystemExit):
        nuk.org_get(org, "facilities.nope")


# --- org resolution from git remote ------------------------------------------


def test_origin_org_from_github_url(monkeypatch):
    monkeypatch.setattr(nuk, "git_origin", lambda _p: "https://github.com/ekd-akd/oauth")
    assert nuk.origin_org() == "ekd-akd"


def test_origin_org_none_without_remote(monkeypatch):
    monkeypatch.setattr(nuk, "git_origin", lambda _p: None)
    assert nuk.origin_org() is None
