#!/usr/bin/env python3
"""Typer CLI: command surface."""

from __future__ import annotations

import os
import shutil
import subprocess  # noqa: S404
import sys
from pathlib import Path  # noqa: TC003
from typing import Annotated

import typer
import yaml

import nuk

# --- typer CLI ----------------------------------------------------------------

_EPILOG = """\
Manifest (apiVersion: nuk/v1, kind: Deployment):
  metadata.name, spec.source.{repo,branch}, spec.compose.file,
  spec.ingress[].{host,service,port}, spec.envFrom[].secretRef
  spec.ingress[] also takes optional: path (PathPrefix), stripPrefix,
    priority, www (301 www.<host> -> <host>; apex domains only),
    auth ("basic" -> HTTP Basic Auth; refused unless a Facility provides the capability)
  spec.envFrom[].secretRef -> existing env files injected into each
    ingress service's container env via the compose override (and also
    passed to `docker compose --env-file` for ${VAR} interpolation).
  spec.databases: {postgres: true, redis: true} -> per-app DB on the
    shared data stack; injects DATABASE_URL / REDIS_URL into the
    ingress service(s). Override the injection target with
    databases.attachTo: [web, worker] (explicit services, e.g. a worker
    with no ingress) or databases.attachAll: true (every compose service).
"""

app = typer.Typer(
    name="nuk",
    help="Minimal Kubernetes-shaped Docker Compose deployer.",
    epilog=_EPILOG,
    add_completion=True,
    no_args_is_help=True,
)


def _version(value: bool) -> None:
    """Eager `--version` callback: print `nuk <version>` and exit 0.

    Fires before the host-check in the app callback, so `nuk --version` works on
    any machine (the controller CD smoke check relies on this).

    Args:
        value: Whether `--version` was passed.

    Raises:
        typer.Exit: Always, when `value` is set, after printing.
    """
    if value:
        print(f"nuk {nuk.__version__}")
        raise typer.Exit


@app.callback()
def _root(
    ctx: typer.Context,
    version: Annotated[  # noqa: ARG001  # consumed by the eager callback before the body runs
        bool,
        typer.Option("--version", callback=_version, is_eager=True, help="print version and exit"),
    ] = False,
) -> None:
    """Guard every subcommand on the controller host.

    Runs after the eager `--version` callback, so `--version`/`--help` never trip
    the host check, but every actual subcommand does.

    Args:
        ctx: The typer context, used to echo the invoked subcommand in the error.
        version: Whether `--version` was passed (handled by the eager callback).

    Raises:
        NukError: When `/opt/nuklaut` is absent (nuk runs on the controller).
            The `org` and `update` subcommands are exempt — they run off the
            controller too (operator workstation, CI, the deploy plugin).
    """
    if ctx.invoked_subcommand in {"org", "update"}:
        return
    if not nuk.paths.ROOT.exists():
        nuk.die(
            f"nuk: {nuk.paths.ROOT} does not exist — nuk runs on the controller, "
            f"not your workstation. Use: ./deploy.nuk.sh nuk {ctx.invoked_subcommand}"
        )


@app.command("list")
@app.command("get")
@app.command("ls")
def _list() -> None:
    """List deployments, container state, and ingress hosts (aliases: get, ls)."""
    nuk.cmd_get()


@app.command("apply")
def _apply(
    manifest: Annotated[Path, typer.Argument(help="path to the nuk/v1 manifest")],
    repo_path: Annotated[
        str | None,
        typer.Option(
            "--repo-path",
            help="local path to use instead of cloning spec.source.repo "
            "(for workflow-driven deploys where the runner already has a checkout)",
        ),
    ] = None,
) -> None:
    """Create or update a deployment from a manifest."""
    nuk.cmd_apply(manifest, repo_path)


@app.command("status")
def _status(
    name: Annotated[
        str | None,
        typer.Argument(
            help="deployment name; omit for the org-wide overview",
            autocompletion=nuk.complete_deployment_name,
        ),
    ] = None,
    pretty: Annotated[
        bool,
        typer.Option("--json", help="pretty-print the org-wide overview (always JSON either way)"),
    ] = False,
    show_all: Annotated[
        bool,
        typer.Option(
            "--all",
            help="org-wide: also compare against the declared org manifest (needs --org-file)",
        ),
    ] = False,
    org_file: Annotated[
        Path | None,
        typer.Option("--org-file", help="path to nuklaut.org.yml (required with --all)"),
    ] = None,
    probe: Annotated[
        bool,
        typer.Option(
            "--probe",
            help="org-wide: best-effort outbound HTTPS probe per ingress host (off by default)",
        ),
    ] = False,
) -> None:
    """Show one app's health/ingress/databases/source (NAME), or the org-wide overview as JSON."""
    if name is not None:
        nuk.cmd_status(name)
        return
    nuk.cmd_status_overview(pretty=pretty, show_all=show_all, org_file=org_file, probe=probe)


@app.command("logs")
def _logs(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=nuk.complete_deployment_name)
    ],
) -> None:
    """Follow compose logs for a deployment."""
    nuk.cmd_logs(name)


@app.command("rollout")
def _rollout(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=nuk.complete_deployment_name)
    ],
) -> None:
    """Git pull + compose pull + up -d."""
    nuk.cmd_rollout(name)


@app.command("rollback")
def _rollback(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=nuk.complete_deployment_name)
    ],
    to: Annotated[
        int | None,
        typer.Option("--to", help="history index to restore (default: the previous release)"),
    ] = None,
    show: Annotated[
        bool, typer.Option("--list", help="print the release history and apply nothing")
    ] = False,
) -> None:
    """Re-apply a previously recorded release."""
    nuk.cmd_rollback(name, to, show)


@app.command("converge")
def _converge(
    sources: Annotated[
        Path, typer.Option("--sources", help="sources.yml: repos, deploy keys, what each applies")
    ] = nuk.paths.SOURCES_FILE,
    signers_dir: Annotated[
        Path, typer.Option("--signers-dir", help="allowed_signers.d: one trust file per source")
    ] = nuk.paths.SIGNERS_DIR,
    state_dir: Annotated[
        Path, typer.Option("--state-dir", help="lock, per-source state, status file")
    ] = nuk.paths.CONVERGE_STATE,
) -> None:
    """Converge this host from every source to its newest verifying tag (spec §7)."""
    raise typer.Exit(
        nuk.cmd_converge(sources_file=sources, signers_dir=signers_dir, state_dir=state_dir)
    )


@app.command("delete")
def _delete(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=nuk.complete_deployment_name)
    ],
    purge: Annotated[
        bool,
        typer.Option(
            "--purge", help="also drop the app's postgres db/role + redis user (DESTROYS DATA)"
        ),
    ] = False,
) -> None:
    """Tear down a deployment (keeps its database)."""
    nuk.cmd_delete(name, purge)


db_app = typer.Typer(
    name="db", help="inspect/manage app databases (shared postgres/redis)", no_args_is_help=True
)
app.add_typer(db_app)


@db_app.command("ls")
def _db_ls() -> None:
    """List managed databases; flags retained ones with no deployment."""
    nuk.cmd_db_ls()


@db_app.command("purge")
def _db_purge(
    name: Annotated[
        str, typer.Argument(help="deployment name", autocompletion=nuk.complete_db_name)
    ],
) -> None:
    """Drop a retained app's database + creds."""
    nuk.cmd_db_purge(name)


def _uv_bin_dir() -> str | None:
    """The directory the running `nuk` shim lives in, or None if unresolvable.

    `uv tool install` writes its entry point into `UV_TOOL_BIN_DIR` (default
    `~/.local/bin`), which on a fleet host is not on PATH while the converge unit
    runs `/usr/local/bin/nuk converge` — so a bare `nuk update` moves the shim and
    breaks the timer. Pinning the install to the shim's own directory keeps the
    command that invoked us working.
    """
    exe = shutil.which("nuk") or sys.argv[0]
    if not exe:
        return None
    path = Path(exe)
    # Deliberately not `.resolve()`: the shim is a symlink INTO the tool venv, and
    # it is the shim's own directory (e.g. `/usr/local/bin`) that must receive the
    # new one.
    return str((path if path.is_absolute() else Path.cwd() / path).parent)


def cmd_update(to: str | None, check: bool) -> None:
    """Install the latest nuk release (or an explicit ref) via `uv tool install`.

    Args:
        to: Explicit ref/tag to install (bypasses the up-to-date check, so it also
            supports pinning/downgrade); None installs the latest release.
        check: Only report installed-vs-latest; install nothing.

    Raises:
        NukError: If the latest release cannot be resolved, or the uv install fails.
    """
    current = nuk.__version__
    target = to or nuk.latest_release_tag()
    if not target:
        nuk.die("nuk update: could not resolve the latest release (network?). Pass --to <ref>.")
    if check:
        print(f"nuk {current} installed - latest is {target}")
        return
    if to is None and nuk.norm_ver(target) and nuk.norm_ver(target) <= nuk.norm_ver(current):
        print(f"nuk {current} is already up to date ({target})")
        return
    print(f"updating nuk {current} -> {target} via uv tool install...")
    bin_dir = _uv_bin_dir()
    env = {**os.environ, "UV_TOOL_BIN_DIR": bin_dir} if bin_dir else None
    try:
        nuk.sh(
            "uv", "tool", "install", "--force", "--from", f"{nuk.NUK_GIT}@{target}", "nuk", env=env
        )
    except (subprocess.SubprocessError, OSError) as e:
        hint = f"UV_TOOL_BIN_DIR={bin_dir} " if bin_dir else ""
        nuk.die(
            f"nuk update: uv install failed ({e}). Is uv installed? "
            f"Manual: {hint}uv tool install --from {nuk.NUK_GIT}@{target} nuk"
        )
    print(f"nuk updated to {target} - run `nuk --version` to confirm")


def _emit(value: object) -> str:
    """Render an org value for the shell: bools lowercased, blocks as YAML, else str."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return yaml.safe_dump(value, sort_keys=False).rstrip()
    return str(value)


org_app = typer.Typer(
    name="org",
    help="resolve + read the org capability manifest (nukorg/v1) — runs off-controller",
    no_args_is_help=True,
)
app.add_typer(org_app)


@org_app.command("resolve")
def _org_resolve(
    repo_path: Annotated[
        str, typer.Option("--repo-path", help="git checkout to read origin from")
    ] = ".",
) -> None:
    """Print the GitHub org of a repo's origin (its `<org>/infra` holds the manifest)."""
    org = nuk.origin_org(repo_path)
    if not org:
        nuk.die("nuk org resolve: no github origin remote found")
    print(org)


@org_app.command("validate")
def _org_validate(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
) -> None:
    """Validate a nukorg/v1 Org manifest; exit nonzero if invalid."""
    org = nuk.load_org(path)
    print(f"OK: {path} is a valid nukorg/v1 Org ({org.metadata.name})")


@org_app.command("get")
def _org_get(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
    key: Annotated[str, typer.Argument(help="dotted key, e.g. facilities.dnsProvider")],
) -> None:
    """Print one value from an Org manifest by dotted key (for bootstrap + plugin)."""
    print(_emit(nuk.org_get(nuk.load_org(path), key)))


@org_app.command("show")
def _org_show(
    path: Annotated[Path, typer.Argument(help="path to nuklaut.org.yml")],
) -> None:
    """Print the validated Org manifest as normalized YAML."""
    print(yaml.safe_dump(nuk.load_org(path).model_dump(by_alias=True), sort_keys=False), end="")


@app.command("update")
def _update(
    to: Annotated[
        str | None, typer.Option("--to", help="ref/tag to install (default: latest release)")
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="report installed vs latest; install nothing")
    ] = False,
) -> None:
    """Update the installed nuk to the latest release (or --to <ref>) via uv."""
    cmd_update(to, check)


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
