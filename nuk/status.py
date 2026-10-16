#!/usr/bin/env python3
"""Status overview (nukview data-layer port)."""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path  # noqa: TC003
from typing import Literal

import nuk

# --- status overview (nukview data-layer port) ---------------------------------
# Ported from nukview's server-only data layer (buildOverview/readApp/driftFor in
# nukview's $lib/server/nuk.ts) so the overview logic lives in ONE place; nukview
# becomes a thin renderer over this JSON. Field names mirror nukview's types.ts
# by key so the renderer needs no remap. Every field degrades on a missing
# source — this never throws out of build_overview().


def _git_provenance(repo_dir: Path) -> nuk.GitProvenance:
    """Full commit sha + committer date + github web URL for `repo_dir`'s HEAD.

    Returns the empty nuk.GitProvenance when there is no checkout / no commit — the
    caller degrades that field rather than failing.
    """
    out = nuk._git_try(repo_dir, "log", "-1", "--format=%H%x09%cI")
    if not out:
        return nuk.GitProvenance()
    full_commit, _, date = out.partition("\t")
    return nuk.GitProvenance(
        full_commit=full_commit,
        last_commit=date or None,
        repo_url=nuk.git_origin(str(repo_dir)),
    )


_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def _read_version(repo_dir: Path) -> str | None:
    """Best-effort app version: pyproject.toml > package.json > `git describe`.

    Mirrors nukview's readVersion — the controller checkout has no tags, so
    version files win; `git describe` is the floor and degrades to a short sha.
    """
    pyproject = repo_dir / "pyproject.toml"
    if pyproject.exists():
        m = _VERSION_RE.search(pyproject.read_text(encoding="utf-8"))
        if m:
            return m.group(1)
    data = nuk._read_json_safe(repo_dir / "package.json")
    version = data.get("version") if isinstance(data, dict) else None
    if isinstance(version, str):
        return version
    return nuk._git_try(repo_dir, "describe", "--tags", "--always", "--abbrev=7")


def _list_workflows(repo_dir: Path) -> list[nuk.Workflow]:
    """GitHub Actions workflows in `repo_dir`, with normalised trigger events."""
    wf_dir = repo_dir / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    out: list[nuk.Workflow] = []
    for f in sorted(wf_dir.iterdir()):
        if f.suffix not in {".yml", ".yaml"}:
            continue
        doc = nuk._read_yaml_safe(f)
        doc = doc if isinstance(doc, dict) else {}
        # YAML 1.1 parses the bare key `on:` as the boolean True — PyYAML follows
        # that resolver, so a GitHub Actions workflow's trigger key lands under
        # `True`, not the string "on". Check both.
        on = doc.get("on", doc.get(True))
        if isinstance(on, str):
            triggers = [on]
        elif isinstance(on, list):
            triggers = [str(t) for t in on]
        elif isinstance(on, dict):
            triggers = [str(k) for k in on]
        else:
            triggers = []
        name = doc.get("name")
        wf_name = name if isinstance(name, str) else f.name
        out.append(nuk.Workflow(f.name, wf_name, triggers))
    return out


def _dynamic_routers(name: str) -> list[nuk.RouterStatus] | None:
    """Router id/rule pairs nuk rendered into the Traefik file provider for `name`."""
    doc = nuk._read_yaml_safe(nuk._router_file(name))
    http = doc.get("http") if isinstance(doc, dict) else None
    routers = http.get("routers") if isinstance(http, dict) else None
    if not isinstance(routers, dict) or not routers:
        return None
    out: list[nuk.RouterStatus] = []
    for rid, r in routers.items():
        rule = r.get("rule") if isinstance(r, dict) else None
        out.append(nuk.RouterStatus(rid, rule if isinstance(rule, str) else "", None))
    return out


def _probe(host: str, timeout: float = 2.5) -> str | None:
    """Black-box "is it serving?" — outbound HTTPS HEAD, never Docker.

    Any HTTP answer (incl. 3xx/4xx) means Traefik routed to a live backend;
    >=500 means the backend is down / showing the maintenance page. An
    unreachable host (DNS, TLS, timeout, connection refused) is unknown (None),
    not "missing" — nuk cannot tell "no DNS" from "not my problem" from here.
    """
    req = urllib.request.Request(f"https://{host}/", method="HEAD")  # noqa: S310  # fixed https scheme
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # fixed https scheme
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except (urllib.error.URLError, OSError, TimeoutError):
        return None
    return "missing" if status >= 500 else "enabled"  # noqa: PLR2004  # HTTP status code, not a magic number


def _annotate_routers(
    routers: list[nuk.RouterStatus] | None, hosts: list[str]
) -> list[nuk.RouterStatus]:
    """Attach a best-effort live probe to each router, matched by its rule's host."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        live_by_host = dict(zip(hosts, pool.map(nuk._probe, hosts), strict=True))
    out: list[nuk.RouterStatus] = []
    for r in routers or []:
        host = next((h for h in hosts if f"`{h}`" in r.rule), None)
        out.append(replace(r, live=live_by_host.get(host) if host else None))
    return out


def _drift_for(
    hosts: list[str], routers: list[nuk.RouterStatus] | None
) -> Literal["in-sync", "drift", "unknown"]:
    """Two-file consistency check between the manifest's hosts and Traefik's routers.

    Does every manifest ingress host appear in a router nuk actually rendered?
    Compares two files nuk itself wrote — never re-renders. Returns "unknown"
    when there are no hosts to check, "drift" when the dynamic file is missing
    or a host is absent from it, else "in-sync".
    """
    if not hosts:
        return "unknown"
    if routers is None:
        return "drift"
    blob = " ".join(r.rule for r in routers)
    return "in-sync" if all(f"`{h}`" in blob for h in hosts) else "drift"


def _overview_ingress_fields(spec: object) -> tuple[list[str], list[nuk.AppIngress]]:
    """Deduped host list + full ingress view list from a manifest's `spec.ingress`."""
    raw = spec.get("ingress") if isinstance(spec, dict) else None
    entries = raw if isinstance(raw, list) else []
    ingress = [a for a in map(nuk.AppIngress.from_wire, entries) if a is not None]
    hosts = list(dict.fromkeys(a.host for a in ingress))
    return hosts, ingress


def _overview_features(spec: object) -> nuk.AppFeatures:
    """`spec.databases` -> the declared-backing-services view."""
    data = spec if isinstance(spec, dict) else {}
    return nuk.AppFeatures.from_databases(data.get("databases"))


def _overview_provenance(
    name: str, source: nuk.AppSource | None
) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    """commit/commitUrl/repoUrl/lastCommit/imageDigest, provenance.json-first.

    Returns:
        (commit, commit_url, repo_url, last_commit, image_digest) — each None
        when its source is unavailable.
    """
    repo_dir = nuk._repo_dir(name)
    provenance = nuk.read_provenance(name)
    git_prov = _git_provenance(repo_dir)

    full_commit = (provenance.commit if provenance else None) or git_prov.full_commit
    commit = full_commit[:12] if full_commit else None

    web = git_prov.repo_url
    commit_url = f"{web}/commit/{full_commit}" if web and full_commit else None
    declared_repo_url = nuk.github_url(source.repo) if source and source.repo else None
    return (
        commit,
        commit_url,
        declared_repo_url or web,
        git_prov.last_commit,
        provenance.image_digest if provenance else None,
    )


def _read_app_overview(name: str, *, probe_enabled: bool = False) -> nuk.AppOverview:
    """Build one app's nuk.Overview entry from on-disk state. Degrades; never raises."""
    notes: list[str] = []
    manifest_raw = nuk._read_yaml_safe(nuk._manifest_file(name))
    if manifest_raw is None:
        notes.append("manifest.yml unreadable")
    spec = manifest_raw.get("spec") if isinstance(manifest_raw, dict) else None
    spec = spec if isinstance(spec, dict) else {}

    hosts, ingress = _overview_ingress_fields(spec)
    source_raw = spec.get("source")
    source = (
        nuk.AppSource.from_wire(source_raw) if isinstance(source_raw, dict) and source_raw else None
    )

    commit, commit_url, repo_url, last_commit, image_digest = _overview_provenance(name, source)
    if not commit:
        notes.append("no git checkout / commit unavailable")

    repo_dir = nuk._repo_dir(name)
    routers = _dynamic_routers(name)
    routers_out = _annotate_routers(routers, hosts) if probe_enabled else (routers or [])

    return nuk.AppOverview(
        name=name,
        hosts=hosts,
        source=source,
        repo_url=repo_url,
        commit=commit,
        commit_url=commit_url,
        last_commit=last_commit,
        version=_read_version(repo_dir),
        routers=routers_out,
        drift=_drift_for(hosts, routers),
        features=_overview_features(spec),
        workflows=_list_workflows(repo_dir),
        ingress=ingress,
        notes=notes,
        image_digest=image_digest,
    )


def build_overview(*, probe_enabled: bool = False) -> nuk.Overview:
    """Walk DEPLOYS/*/ and build the org-wide status nuk.Overview. Degrades; never raises."""
    errors: list[str] = []
    names: list[str] = []
    if nuk.paths.DEPLOYS.exists():
        names = sorted(p.name for p in nuk.paths.DEPLOYS.iterdir() if p.is_dir())
    else:
        errors.append(f"cannot read {nuk.paths.DEPLOYS} — is /opt/nuklaut mounted?")
    return nuk.Overview(
        apps=[_read_app_overview(n, probe_enabled=probe_enabled) for n in names],
        live_routing_available=False,  # Traefik api@internal integration is a later chapter
        nuk_root=str(nuk.paths.ROOT),
        generated_at=nuk._iso_utc_now(),
        errors=errors,
    )


def _soll_vs_ist(overview: nuk.Overview, org_file: Path | None) -> nuk.Overview:
    """`--all`: declared org hosts (soll) vs this command's local observation (ist).

    Args:
        overview: The already-built nuk.Overview (read for its observed app count).
        org_file: Path to the org manifest (`nuklaut.org.yml`); required.

    Returns:
        The overview with the `--all` blocks (`hosts`, `sollVsIst`) set.

    Raises:
        NukError: When `org_file` is not given, or is not a valid Org manifest.
    """
    if org_file is None:
        nuk.die("nuk status --all: --org-file PATH is required (path to nuklaut.org.yml)")
    org = nuk.load_org(org_file)
    return replace(
        overview,
        hosts=org.hosts,
        soll_vs_ist=nuk.SollVsIst(
            declared_hosts=len(org.hosts),
            # TODO(K2.5): per-host observed via DOCKER_HOST fan-out (ssh per host,  # noqa: FIX002
            # one nuk status per host, merge). Kapitel 1 is single-host, so
            # "observed" is just this controller — the one this command runs on.
            observed_hosts=1,
            declared_apps=None,  # nukorg/v1 does not declare apps (yet)
            observed_apps=len(overview.apps),
        ),
    )
