#!/usr/bin/env python3
"""Filesystem layout of a nuklaut host.

Every path nuk reads or writes at a fixed location lives here, so the modules that
use them never have to reach back into the package root. Deploy state is under
``/opt/nuklaut/``, the convergence loop's state and release history under
``/var/lib/nuk/``, host identity and trust anchors under ``/etc/nuklaut/``.

Import the module and read the attribute (``paths.DEPLOYS``) rather than binding
the value, so a test that redirects a location is seen by every consumer.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path("/opt/nuklaut")
DEPLOYS = ROOT / "deployments"
DYNAMIC = ROOT / "traefik" / "dynamic"
SECRETS = ROOT / "secrets"

# This host's identity, written world-readable (no secrets) by cloud-init. Absent on a
# legacy single-host controller -> read_self() defaults to an entry role (byte-identical).
HOST_ENV = Path("/etc/nuklaut/host.env")

# The convergence loop's state (spec §7). /var/lib per the FHS: machine-local,
# persistent, not configuration. Held apart from /opt/nuklaut so that wiping a
# host's deployments does not also erase the downgrade guard's memory.
CONVERGE_STATE = Path("/var/lib/nuk")
# Only the CLI default: cmd_converge derives both files from its state_dir argument,
# so the tests get a tmp_path and the host gets /var/lib/nuk.
CONVERGE_STATUS = CONVERGE_STATE / "converge-status.json"
# Which repos this host converges from, each with its read-only deploy key and what it
# may change here (contracts C3). Delivered by seed.sh, never by the repos it lists.
SOURCES_FILE = Path("/etc/nuklaut/sources.yml")
# One signers file per source, named after it: a tenant's key can verify that tenant's
# tags and nobody else's (contracts C3). Plain `git verify-tag`, no principal flag.
SIGNERS_DIR = Path("/etc/nuklaut/allowed_signers.d")
# github.com's host key, pinned by cloud-init; the deploy-key fetch never trusts on first use.
KNOWN_HOSTS = Path("/etc/nuklaut/known_hosts")

# The fleet DB seed: delivered by converge.sh via the existing sops channel to
# the data + app hosts only. Both hosts derive per-app passwords from it, so no
# credential is ever transported (spec §3.1).
DB_SEED_ENV = Path("/etc/nuklaut/secrets/db-seed.env")

RELEASES = CONVERGE_STATE / "releases"
