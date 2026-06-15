# nuk

`nuk` is a single-file Python CLI — a **minimal, Kubernetes-shaped Docker Compose
deployer**. You give it a small `nuk/v1` manifest; it reconciles a git repo + a
docker-compose project + Traefik ingress + optional per-app Postgres/Redis into
running state. No daemon, no database — all state lives in `/opt/nuklaut/` on the
controller host.

It runs on the **nuklaut controller** (a single Hetzner VPS behind Traefik), not on
your workstation (it refuses to run if `/opt/nuklaut` is absent). nuk ships as a
versioned `nuk.pyz`; the controller installs a pinned release. The CLI is built with
**typer** and validates manifests with **pydantic**, but those (plus PyYAML) are
**bundled into the `nuk.pyz` by shiv** at release time — so the controller still needs
only **python3** and the `docker` CLI on the host, nothing else installed.

## Manifest (`nuk/v1`)

```yaml
apiVersion: nuk/v1
kind: Deployment
metadata:
  name: my-app                          # also the docker-compose project name
spec:
  source:
    repo: https://github.com/me/my-app.git
    branch: main                        # default: main
  compose:
    file: docker-compose.yml            # path inside the repo; default: docker-compose.yml
  ingress:                              # optional; one Traefik router per entry
    - host: app.astrojones.de
      service: web                      # compose service name
      port: 8080                        # container port to proxy to
      # optional, all backward-compatible:
      # path: /api                      # adds PathPrefix(`/api`) to the rule
      # stripPrefix: true               # strip `path` before proxying (needs path)
      # priority: 100                   # explicit router priority
      # www: true                       # also 301 www.<host> -> <host> (apex only)
      # auth: oauth                     # gate via the oauth2-proxy GitHub forwardAuth chain
  envFrom:                              # optional; merged into docker compose --env-file
    - secretRef: /opt/nuklaut/secrets/my-app.env
  databases:                            # optional; shared postgres/redis, per-app
    postgres: true                      # -> DATABASE_URL (pgvector); or { driver: asyncpg }
    redis: true                         # -> REDIS_URL (own ACL user, key prefix my-app:)
```

This shape maps 1:1 to Kubernetes (the intended migration path):

| nuk field                      | k8s equivalent                                    |
| ------------------------------ | ------------------------------------------------- |
| `spec.source` + `spec.compose` | `kind: Deployment` (pods built from compose)      |
| `spec.ingress`                 | `kind: Ingress` (one rule per entry, TLS preset)  |
| `spec.envFrom[].secretRef`     | `envFrom: [{ secretRef: { name: ... } }]`         |
| `spec.databases`               | per-app DB/role + Secret on a shared instance     |

## Subcommands

```bash
nuk apply <manifest>          # create / update (provisions any requested databases)
nuk list                      # deployments, container state, ingress hosts (aliases: get, ls)
nuk logs <name>               # docker compose logs -f
nuk rollout <name>            # git pull + compose pull + up -d
nuk delete <name>             # tear down; KEEPS the database
nuk delete <name> --purge     # also drop the app's postgres db/role + redis user (DESTROYS DATA)
nuk db ls                     # list managed databases; flags retained ones with no deployment
nuk db purge <name>           # drop a retained app's database + creds
```

## What `nuk apply` does

1. `git clone --branch <branch>` (or `git pull --ff-only`) into
   `/opt/nuklaut/deployments/<name>/repo` — or, with `--repo-path <dir>`, mirrors an
   existing checkout (used by the CI runner, avoiding any git auth on the controller).
2. If `spec.databases` is set, provisions a per-app Postgres role+database (pgvector
   enabled) and/or a Redis ACL user on the shared data stack, writing the generated
   `DATABASE_URL` / `REDIS_URL` to `/opt/nuklaut/secrets/<name>-db.env` (600).
3. Writes `/opt/nuklaut/deployments/<name>/compose.override.yml` joining each ingress
   service to the external `edge` network (and the private `data` network + the creds
   `env_file` when a database was requested) — so your compose file stays Traefik- and
   DB-agnostic.
4. Writes `/opt/nuklaut/traefik/dynamic/<name>.yml` with one Traefik router + service
   per ingress entry (TLS via the `letsencrypt` resolver).
5. Copies the manifest to `/opt/nuklaut/deployments/<name>/manifest.yml`.
6. `docker compose -p <name> ... up -d`. (No `--pull`: images are pre-pulled into the
   shared daemon by the deploy workflow, which has GHCR auth; the controller does not.)

## Databases (shared postgres + redis)

`spec.databases` provisions per-app access on a shared data stack — one
`nuk-postgres` (pgvector) and one `nuk-redis` on a **private `data` network Traefik
never touches**:

- A Postgres role + database named after the app (idempotent), `vector` extension
  enabled, with `CONNECT` revoked from everyone but the owner.
- A Redis ACL user restricted to keys/channels prefixed `<app>:` with dangerous
  commands removed (no `FLUSHALL` on the shared instance).
- Passwords generated **once** and stored in `/opt/nuklaut/secrets/<app>-db.env`
  (600); re-applies reuse them (no credential churn).
- `postgres: { driver: asyncpg }` emits `postgresql+asyncpg://…` for SQLAlchemy/asyncpg
  apps; bare `true` yields a libpq `postgresql://` URL.

Admin paths never need a TCP password — provisioning runs `docker exec` against the
shared containers (Postgres local-socket trust; Redis admin password from the
container's own env), so DB superuser secrets never reach a host process-arg line.

`nuk delete <app>` keeps the database (the creds file is the ownership marker, so nuk
still tracks it via `nuk db ls`); `--purge` / `nuk db purge` is the only path that
destroys data.

## Development

```bash
uv run pytest          # unit tests for the pure render + db-helper functions (no controller)
uv run ruff check      # lint
uv run ty check        # type-check
```

Tests exercise `build_ingress` / `build_override` and the database helpers entirely
in-process; they need no controller. The render functions stay dict-in/dict-out (their
YAML output is a Traefik/compose wire contract); pydantic validates only at the
manifest `load()` boundary and in the command layer.

## Releasing

Push a `vX.Y.Z` tag. CI (`.github/workflows/release.yml`) builds a self-contained
`nuk.pyz` with **shiv** (under python 3.11, to match the controller ABI), bundling the
project plus its runtime deps — pydantic, typer, PyYAML — into the single artifact, and
attaches it to the GitHub release. The **nuklaut** infra repo pins a release via
`NUK_VERSION` and installs that artifact to `/usr/local/bin/nuk` (host) and bakes it into
the GitHub Actions runner image during `bootstrap.sh`.

## Deployment

nuk is operated by the **nuklaut** controller. Org repos deploy themselves via the
`astrojones/.github` reusable `nuk-deploy.yml` workflow on the org self-hosted runner
(label `nuklaut`): the manifest lives at `.nuklaut/deployment.yml`, the image goes to
`ghcr.io/<owner>/<repo>`, and per-app secrets live at `/opt/nuklaut/secrets/<repo>.env`.
 
