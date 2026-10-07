"""Unit tests for `nuk status` (K1.5.1: org-wide JSON overview) and
provenance-on-apply (K1.5.2).

Ported from nukview's server-only data layer (buildOverview/readApp/driftFor);
these tests pin the same semantics in nuk itself. Pure pyyaml/pydantic + a real
throwaway git checkout for provenance — no docker, no network, no /opt/nuklaut.

    uv run pytest tests/test_nuk_status.py
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

import nuk
import pytest
import yaml

# --- fixtures -------------------------------------------------------------------


def _git_repo(repo_dir, *, message="init"):
    """Create a real one-commit git checkout at repo_dir; return its full HEAD sha."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "GIT_AUTHOR_NAME": "nuk-test",
        "GIT_AUTHOR_EMAIL": "nuk-test@example.com",
        "GIT_COMMITTER_NAME": "nuk-test",
        "GIT_COMMITTER_EMAIL": "nuk-test@example.com",
        "PATH": __import__("os").environ.get("PATH", ""),
    }
    subprocess.run(["git", "init", "--quiet"], cwd=repo_dir, check=True, env=env)  # noqa: S603, S607
    subprocess.run(  # noqa: S603, S607
        ["git", "commit", "--allow-empty", "--quiet", "-m", message],
        cwd=repo_dir,
        check=True,
        env=env,
    )
    subprocess.run(  # noqa: S603, S607
        ["git", "remote", "add", "origin", "git@github.com:astrojones/app.git"],
        cwd=repo_dir,
        check=True,
        env=env,
    )
    sha = subprocess.run(  # noqa: S603, S607
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()
    return sha


def _stand_up(  # noqa: PLR0913  # test fixture helper — one knob per axis under test, kept flat on purpose
    tmp_path,
    monkeypatch,
    *,
    name="app",
    hosts=("app.astrojones.de",),
    with_git=False,
    with_dynamic=True,
    manifest_extra=None,
):
    """Fake /opt/nuklaut layout for one deployment; patches the module roots."""
    root = tmp_path / "opt-nuklaut"
    deploys = root / "deployments"
    dynamic = root / "traefik" / "dynamic"
    secrets = root / "secrets"
    releases = tmp_path / "releases"
    dynamic.mkdir(parents=True)
    secrets.mkdir(parents=True)
    monkeypatch.setattr(nuk, "ROOT", root)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    monkeypatch.setattr(nuk, "DYNAMIC", dynamic)
    monkeypatch.setattr(nuk, "SECRETS", secrets)
    monkeypatch.setattr(nuk, "RELEASES", releases)

    pdir = deploys / name
    pdir.mkdir(parents=True)
    ingress = [{"host": h, "service": "web", "port": 8080} for h in hosts]
    manifest = {
        "apiVersion": "nuk/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {
            "source": {"repo": "https://github.com/astrojones/app", "branch": "main"},
            "ingress": ingress,
        },
    }
    if manifest_extra:
        manifest["spec"].update(manifest_extra)
    (pdir / "manifest.yml").write_text(yaml.safe_dump(manifest), encoding="utf-8")

    if with_dynamic:
        nuk.write_ingress(name, ingress, nuk.DEFAULT_ROUTE_VOCAB)

    sha = None
    if with_git:
        sha = _git_repo(pdir / "repo")

    return pdir, sha


# --- build_overview: top-level shape + graceful degradation ---------------------


def test_build_overview_top_level_shape(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    overview = nuk.build_overview()
    assert set(overview) == {"apps", "liveRoutingAvailable", "nukRoot", "generatedAt", "errors"}
    assert overview["errors"] == []
    assert overview["liveRoutingAvailable"] is False
    assert overview["nukRoot"] == str(nuk.ROOT)
    # generatedAt is a real ISO-8601 UTC timestamp
    datetime.fromisoformat(overview["generatedAt"])
    assert len(overview["apps"]) == 1
    app = overview["apps"][0]
    assert set(app) == {
        "name", "hosts", "source", "repoUrl", "commit", "commitUrl", "lastCommit",
        "version", "routers", "drift", "features", "workflows", "ingress", "notes",
        "imageDigest",
    }  # fmt: skip


def test_build_overview_missing_deploys_degrades(tmp_path, monkeypatch):
    """No /opt/nuklaut/deployments -> empty apps + a top-level error, never raises."""
    monkeypatch.setattr(nuk, "DEPLOYS", tmp_path / "nonexistent" / "deployments")
    overview = nuk.build_overview()
    assert overview["apps"] == []
    assert overview["errors"]
    assert "cannot read" in overview["errors"][0]


def test_build_overview_lists_apps_without_manifest_too(tmp_path, monkeypatch):
    """Mirrors nukview: every DEPLOYS/*/ dir is listed, even sans manifest.yml —
    readApp degrades that entry rather than the dir being skipped.
    """
    root = tmp_path / "opt-nuklaut"
    deploys = root / "deployments"
    (deploys / "ghost").mkdir(parents=True)
    monkeypatch.setattr(nuk, "ROOT", root)
    monkeypatch.setattr(nuk, "DEPLOYS", deploys)
    monkeypatch.setattr(nuk, "DYNAMIC", root / "traefik" / "dynamic")
    overview = nuk.build_overview()
    assert [a["name"] for a in overview["apps"]] == ["ghost"]
    assert "manifest.yml unreadable" in overview["apps"][0]["notes"]
    assert overview["apps"][0]["drift"] == "unknown"


# --- drift: two-file consistency (manifest hosts vs rendered Traefik routers) ---


def test_drift_in_sync_when_host_is_rendered():
    routers = [{"id": "app-0", "rule": "Host(`app.astrojones.de`)", "live": None}]
    assert nuk._drift_for(["app.astrojones.de"], routers) == "in-sync"


def test_drift_when_dynamic_file_missing():
    assert nuk._drift_for(["app.astrojones.de"], None) == "drift"


def test_drift_when_host_absent_from_rendered_routers():
    routers = [{"id": "app-0", "rule": "Host(`other.astrojones.de`)", "live": None}]
    assert nuk._drift_for(["app.astrojones.de"], routers) == "drift"


def test_drift_unknown_when_no_ingress_hosts():
    assert nuk._drift_for([], None) == "unknown"
    assert nuk._drift_for([], [{"id": "x", "rule": "", "live": None}]) == "unknown"


def test_read_app_overview_drift_in_sync_end_to_end(tmp_path, monkeypatch):
    """apply-rendered dynamic file + manifest hosts -> in-sync, via the real
    write_ingress render path (not a hand-rolled router fixture).
    """
    _stand_up(tmp_path, monkeypatch, with_git=True)
    app = nuk._read_app_overview("app")
    assert app["drift"] == "in-sync"
    assert app["hosts"] == ["app.astrojones.de"]
    assert app["routers"][0]["rule"] == "Host(`app.astrojones.de`)"


def test_read_app_overview_drift_when_dynamic_file_absent(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True, with_dynamic=False)
    app = nuk._read_app_overview("app")
    assert app["drift"] == "drift"
    assert app["routers"] == []


# --- graceful degradation --------------------------------------------------------


def test_read_app_overview_degrades_on_missing_manifest(tmp_path, monkeypatch):
    root = tmp_path / "opt-nuklaut"
    (root / "deployments" / "app").mkdir(parents=True)
    monkeypatch.setattr(nuk, "ROOT", root)
    monkeypatch.setattr(nuk, "DEPLOYS", root / "deployments")
    monkeypatch.setattr(nuk, "DYNAMIC", root / "traefik" / "dynamic")
    app = nuk._read_app_overview("app")
    assert "manifest.yml unreadable" in app["notes"]
    assert app["hosts"] == []
    assert app["source"] is None
    assert app["commit"] is None
    assert app["drift"] == "unknown"


def test_read_app_overview_degrades_on_no_git_checkout(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=False)
    app = nuk._read_app_overview("app")
    assert app["commit"] is None
    assert app["commitUrl"] is None
    assert app["version"] is None
    assert "no git checkout / commit unavailable" in app["notes"]
    # repoUrl still resolves from the manifest's declared source.repo
    assert app["repoUrl"] == "https://github.com/astrojones/app"


# --- provenance.json precedence (K1.5.2) -----------------------------------------


def test_provenance_commit_and_digest_take_precedence_over_git_checkout(tmp_path, monkeypatch):
    pdir, checkout_sha = _stand_up(tmp_path, monkeypatch, with_git=True)
    provenance_sha = "f" * 40
    (pdir / "provenance.json").write_text(
        json.dumps(
            {
                "repo": "https://github.com/astrojones/app",
                "branch": "main",
                "commit": provenance_sha,
                "imageDigest": "sha256:deadbeef",
                "appliedAt": "2026-07-14T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    app = nuk._read_app_overview("app")
    assert app["commit"] == provenance_sha[:12]
    assert app["commit"] != checkout_sha[:12]
    assert app["imageDigest"] == "sha256:deadbeef"


def test_provenance_absent_falls_back_to_git_checkout(tmp_path, monkeypatch):
    _pdir, checkout_sha = _stand_up(tmp_path, monkeypatch, with_git=True)
    app = nuk._read_app_overview("app")
    assert app["commit"] == checkout_sha[:12]
    assert app["imageDigest"] is None


def test_provenance_malformed_json_degrades_to_git_checkout(tmp_path, monkeypatch):
    pdir, checkout_sha = _stand_up(tmp_path, monkeypatch, with_git=True)
    (pdir / "provenance.json").write_text("{not valid json", encoding="utf-8")
    assert nuk.read_provenance("app") is None
    app = nuk._read_app_overview("app")
    assert app["commit"] == checkout_sha[:12]


def test_write_provenance_then_read_provenance_roundtrips(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch)
    nuk.write_provenance(
        "app",
        repo="https://github.com/astrojones/app",
        branch="main",
        commit="a" * 40,
        image_digest=None,
    )
    data = nuk.read_provenance("app")
    assert data["repo"] == "https://github.com/astrojones/app"
    assert data["branch"] == "main"
    assert data["commit"] == "a" * 40
    assert data["imageDigest"] is None
    datetime.fromisoformat(data["appliedAt"])


def test_read_provenance_absent_returns_none(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch)
    assert nuk.read_provenance("app") is None


# --- features (postgres/redis/driver) --------------------------------------------


def test_features_postgres_object_form_captures_driver(tmp_path, monkeypatch):
    _stand_up(
        tmp_path,
        monkeypatch,
        with_git=True,
        manifest_extra={"databases": {"postgres": {"driver": "asyncpg"}, "redis": True}},
    )
    app = nuk._read_app_overview("app")
    assert app["features"] == {"postgres": True, "redis": True, "postgresDriver": "asyncpg"}


def test_features_default_false_when_no_databases(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    app = nuk._read_app_overview("app")
    assert app["features"] == {"postgres": False, "redis": False, "postgresDriver": None}


# --- workflows --------------------------------------------------------------------


def test_workflows_lists_normalised_triggers(tmp_path, monkeypatch):
    pdir, _ = _stand_up(tmp_path, monkeypatch, with_git=True)
    wf_dir = pdir / "repo" / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text(
        yaml.safe_dump({"name": "CI", "on": ["push", "pull_request"]}), encoding="utf-8"
    )
    app = nuk._read_app_overview("app")
    assert app["workflows"] == [
        {"file": "ci.yml", "name": "CI", "triggers": ["push", "pull_request"]}
    ]


def test_workflows_empty_when_no_workflows_dir(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    assert nuk._read_app_overview("app")["workflows"] == []


# --- probe: off by default, no network calls -------------------------------------


def test_probe_disabled_by_default_never_called(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)

    def _boom(host, timeout=2.5):  # noqa: ARG001
        pytest.fail("probe must not run unless explicitly enabled")

    monkeypatch.setattr(nuk, "_probe", _boom)
    app = nuk._read_app_overview("app", probe_enabled=False)
    assert app["routers"][0]["live"] is None


def test_probe_enabled_annotates_routers(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    monkeypatch.setattr(nuk, "_probe", lambda host, timeout=2.5: "enabled")  # noqa: ARG005
    app = nuk._read_app_overview("app", probe_enabled=True)
    assert app["routers"][0]["live"] == "enabled"


# --- cmd_status_overview (the `nuk status` JSON contract) ------------------------


def test_cmd_status_overview_prints_valid_json(tmp_path, monkeypatch, capsys):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    nuk.cmd_status_overview(pretty=False, show_all=False, org_file=None, probe=False)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["apps"][0]["name"] == "app"


def test_cmd_status_overview_pretty_is_still_valid_json(tmp_path, monkeypatch, capsys):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    nuk.cmd_status_overview(pretty=True, show_all=False, org_file=None, probe=False)
    out = capsys.readouterr().out
    assert "\n" in out  # pretty-printed
    json.loads(out)  # still parses


def test_cmd_status_overview_all_requires_org_file(tmp_path, monkeypatch):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    with pytest.raises(SystemExit, match="--org-file"):
        nuk.cmd_status_overview(pretty=False, show_all=True, org_file=None, probe=False)


ONE_HOST_ORG = {
    "apiVersion": "nukorg/v1",
    "kind": "Org",
    "metadata": {"name": "astrojones"},
    "domains": ["astrojones.guru"],
    "platformDomain": "astrojones.guru",
    "acmeEmail": "admin@astrojones.guru",
    "hosts": [
        {
            "name": "hcbase",
            "provider": "hcloud",
            "type": "cx23",
            "role": "all-in-one",
            "privateIp": "10.10.1.2",
        },
    ],
    "facilities": {
        "dns": "wildcard",
        "tls": "dns01",
        "dnsProvider": "hetzner",
        "secrets": "sops",
        "auth": "authentik",
        "runners": "ephemeral",
    },
    "mesh": "none",
}


def test_cmd_status_overview_all_includes_soll_vs_ist(tmp_path, monkeypatch, capsys):
    _stand_up(tmp_path, monkeypatch, with_git=True)
    org_file = tmp_path / "nuklaut.org.yml"
    org_file.write_text(yaml.safe_dump(ONE_HOST_ORG), encoding="utf-8")
    nuk.cmd_status_overview(pretty=False, show_all=True, org_file=org_file, probe=False)
    data = json.loads(capsys.readouterr().out)
    assert data["hosts"] == [
        {
            "name": "hcbase",
            "provider": "hcloud",
            "role": "all-in-one",
            "privateIp": "10.10.1.2",
            "type": "cx23",
            "ip": None,
            "metal": None,
            "vcpu": None,
            "memory": None,
        }
    ]
    assert data["sollVsIst"] == {
        "declaredHosts": 1,
        "observedHosts": 1,
        "declaredApps": None,
        "observedApps": 1,
    }


# --- provenance-on-apply (K1.5.2): wired into cmd_apply --------------------------


def _apply_manifest(tmp_path, monkeypatch, *, name="app"):
    """Stand up an apply-able manifest + a real pre-existing git checkout, and
    monkeypatch `sh` to a no-op recorder so cmd_apply never shells out to real
    git/docker — the pre-seeded repo/ checkout is what provenance reads.
    """
    root = tmp_path / "opt-nuklaut"
    releases = tmp_path / "releases"
    monkeypatch.setattr(nuk, "ROOT", root)
    monkeypatch.setattr(nuk, "DEPLOYS", root / "deployments")
    monkeypatch.setattr(nuk, "DYNAMIC", root / "traefik" / "dynamic")
    monkeypatch.setattr(nuk, "SECRETS", root / "secrets")
    monkeypatch.setattr(nuk, "RELEASES", releases)

    manifest_path = tmp_path / "deployment.yml"
    manifest = {
        "apiVersion": "nuk/v1",
        "kind": "Deployment",
        "metadata": {"name": name},
        "spec": {"source": {"repo": "https://github.com/astrojones/app", "branch": "main"}},
    }
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")

    calls = []
    monkeypatch.setattr(nuk, "sh", lambda *cmd, cwd=None: calls.append(cmd))  # noqa: ARG005

    repo_dir = root / "deployments" / name / "repo"
    sha = _git_repo(repo_dir)
    return manifest_path, sha, calls


def test_apply_writes_provenance_json(tmp_path, monkeypatch):
    manifest_path, sha, _calls = _apply_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: "sha256:cafef00d")  # noqa: ARG005
    nuk.cmd_apply(manifest_path, None)
    provenance = nuk.read_provenance("app")
    assert provenance["repo"] == "https://github.com/astrojones/app"
    assert provenance["branch"] == "main"
    assert provenance["commit"] == sha
    assert provenance["imageDigest"] == "sha256:cafef00d"
    datetime.fromisoformat(provenance["appliedAt"])


def test_apply_surfaces_provenance_through_status(tmp_path, monkeypatch):
    manifest_path, sha, _calls = _apply_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: None)  # noqa: ARG005
    nuk.cmd_apply(manifest_path, None)
    app = nuk._read_app_overview("app")
    assert app["commit"] == sha[:12]


def test_apply_does_not_fail_when_provenance_write_fails(tmp_path, monkeypatch, capsys):
    manifest_path, _sha, _calls = _apply_manifest(tmp_path, monkeypatch)
    monkeypatch.setattr(nuk, "_resolve_image_digest", lambda name, raw: None)  # noqa: ARG005

    def _boom(*a, **k):
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(nuk, "write_provenance", _boom)
    nuk.cmd_apply(manifest_path, None)  # must not raise
    out = capsys.readouterr().out
    assert "provenance not recorded" in out


# --- _resolve_image_digest: best-effort, degrades on any docker failure ---------


def test_resolve_image_digest_happy_path(monkeypatch):
    def fake_run(cmd, **kwargs):  # noqa: ARG001
        if "images" in cmd:
            rows = [{"Repository": "ghcr.io/astrojones/app", "Tag": "latest"}]
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(rows))
        if cmd[0] == "docker" and cmd[1] == "inspect":
            return subprocess.CompletedProcess(
                cmd, 0, stdout="ghcr.io/astrojones/app@sha256:abc123\n"
            )
        raise AssertionError(cmd)

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    digest = nuk._resolve_image_digest("app", {"spec": {}})
    assert digest == "ghcr.io/astrojones/app@sha256:abc123"


def test_resolve_image_digest_degrades_when_docker_unavailable(monkeypatch):
    def fake_run(cmd, **kwargs):  # noqa: ARG001
        raise FileNotFoundError

    monkeypatch.setattr(nuk.subprocess, "run", fake_run)
    assert nuk._resolve_image_digest("app", {"spec": {}}) is None


def test_resolve_image_digest_degrades_on_empty_images_output(monkeypatch):
    monkeypatch.setattr(
        nuk.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=""),  # noqa: ARG005
    )
    assert nuk._resolve_image_digest("app", {"spec": {}}) is None


# --- _parse_compose_images_json: tolerate null rows and malformed input --------
# `docker compose images --format json` prints a bare `null` (exit 0) for an
# empty project; the parser must drop non-dict rows rather than hand `[None]`
# back to callers. Pure function — no docker, no shell.


def test_parse_compose_images_json_null_scalar_is_empty():
    assert nuk._parse_compose_images_json("null") == []


def test_parse_compose_images_json_single_null_array_is_empty():
    assert nuk._parse_compose_images_json("[null]") == []


def test_parse_compose_images_json_drops_null_rows_keeps_dicts():
    assert nuk._parse_compose_images_json('[{"Repository":"x"},null]') == [{"Repository": "x"}]


def test_parse_compose_images_json_parses_json_lines_skipping_blanks():
    text = '{"Repository":"x"}\n\n{"Repository":"y"}\n'
    assert nuk._parse_compose_images_json(text) == [
        {"Repository": "x"},
        {"Repository": "y"},
    ]


def test_parse_compose_images_json_invalid_json_is_empty():
    assert nuk._parse_compose_images_json("not json") == []
