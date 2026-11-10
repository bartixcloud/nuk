# nuk

<p align="center"><em>Kubernetes-shaped deploys for plain Docker Compose. No Kubernetes required.</em></p>

---

**Source code**: <https://github.com/bartixcloud/nuk>

**Releases**: <https://github.com/bartixcloud/nuk/releases>

---

nuk is a small command line tool that deploys Docker Compose apps from a short, declarative manifest.

You describe your app once, in a `nuk/v1` manifest. nuk makes the machine match it: it checks out your repo, wires up Traefik routes and TLS, creates a Postgres database and a Redis user for the app if you ask for them, and runs `docker compose up -d`.

No daemon. No cluster. No database of its own. The state is a handful of files under `/opt/nuklaut/`, and you can read all of them.

The key features are:

* **Short manifests**: a dozen lines of YAML gets you a deployed, HTTPS-enabled app. The shape mirrors Kubernetes (`Deployment`, `Ingress`, `envFrom`), so the day you outgrow Compose, you already know the vocabulary.
* **Your compose file stays yours**: it doesn't need to know about Traefik, networks, or databases. nuk writes a `compose.override.yml` next to it and does the wiring there.
* **Ingress included**: one Traefik router per entry, Let's Encrypt certificates, path prefixes, `www` redirects, and auth gates (`basic` or `oauth`).
* **Databases on demand**: per-app Postgres (with pgvector) and Redis on a shared, private data network. Passwords are generated once and never churn.
* **Safe rollouts**: blue-green with a health gate, one-shot migrations before the switch, and `nuk rollback` when it goes wrong anyway.
* **Fleet-ready**: `nuk converge` pulls signed release tags from your repos and applies them, on every host, forever. It refuses unsigned tags and refuses to walk backwards.
* **Fails closed**: manifests are validated with pydantic. A typo in `auth:` is an error, not a route that quietly ends up public.

## Requirements

* Python 3.13+
* [`uv`](https://docs.astral.sh/uv/), `git`, and Docker with the Compose plugin
* A host set up as a nuklaut controller (nuk expects `/opt/nuklaut/` to exist, with Traefik watching `/opt/nuklaut/traefik/dynamic/`)

nuk is built on [Typer](https://typer.tiangolo.com/) for the CLI and [Pydantic](https://docs.pydantic.dev/) for the manifests.

## Installation

You don't have to install anything to try it. Let `uvx` run it for you:

```console
$ uvx --from git+https://github.com/bartixcloud/nuk nuk --version
```

To install it for real, pin a release tag (see the [releases page](https://github.com/bartixcloud/nuk/releases)):

```console
$ uv tool install --from git+https://github.com/bartixcloud/nuk@<tag> nuk
```

After that, nuk can update itself:

```console
$ nuk update            # latest release
$ nuk update --check    # just report installed vs. latest
$ nuk update --to <tag> # pin or downgrade on purpose
```

There is no PyPI package and no built binary. Installing from a git tag is the whole story, so a tag existing is the whole release.

nuk only does its real work on a controller host. Run on a laptop, every command except `nuk org`, `nuk update`, `--version` and `--help` stops and tells you so.

## Example

### Create it

Say you have an app with a `docker-compose.yml` and a `web` service listening on port 8080. Add a `deployment.yml` to the root of the repo:

```yaml
apiVersion: nuk/v1
kind: Deployment
metadata:
  name: my-app
spec:
  source:
    repo: https://github.com/me/my-app.git
  ingress:
    - host: app.example.com
      service: web
      port: 8080
```

### Apply it

On the controller:

```console
$ nuk apply deployment.yml
```

That's it. nuk cloned the repo, wrote the Traefik router for `app.example.com` (TLS included), and started the stack under the Compose project name `my-app`.

### Check it

```console
$ nuk list
$ nuk status my-app
```

`nuk status` shows container state, ingress and router health, redacted database URLs, and which repo, branch and revision is running.

### Break it, then fix it

Shipped something bad?

```console
$ nuk rollback my-app --list    # what has been released
$ nuk rollback my-app           # back to the previous release
```

### Recap

You wrote a short manifest, ran one command, and got a running, HTTPS-enabled app with a history you can roll back through. Your compose file didn't change.

## The manifest

Here is everything a `Deployment` can say, with the optional parts commented out:

```yaml
apiVersion: nuk/v1
kind: Deployment
metadata:
  name: my-app                      # also the docker compose project name
spec:
  source:
    repo: https://github.com/me/my-app.git
    branch: main                    # default: main
    # unsigned: true                # deploy the branch head, not a signed tag (non-prod only)
  compose:
    file: docker-compose.yml        # path inside the repo; this is the default
  ingress:                          # one Traefik router per entry
    - host: app.example.com
      service: web                  # compose service name
      port: 8080                    # container port to proxy to
      # path: /api                  # adds PathPrefix(`/api`) to the rule
      # stripPrefix: true           # strip `path` before proxying (needs path)
      # priority: 100               # explicit router priority
      # www: true                   # also 301 www.<host> -> <host> (apex domains only)
      # auth: oauth                 # or: basic
      # address: 10.10.2.4:8080     # a backend outside this host, instead of service + port
      # hostPort: 18080             # worker hosts: the published port on the private IP
  envFrom:
    - secretRef: /opt/nuklaut/secrets/my-app.env
    # - sopsFile: secrets/my-app.enc.env
  databases:
    postgres: true                  # or { driver: asyncpg, scratch: true }
    redis: true
    # attachTo: [web, worker]       # inject URLs into these services...
    # attachAll: true               # ...or into every service
  # strategy: ...                   # blue-green rollouts, see below
  # migrate: ...                    # one-shot migration before a rollout, see below
  # placement: { role: app }        # which host role runs it (fleets)
```

If you know Kubernetes, this will look familiar on purpose:

| nuk field                      | Kubernetes equivalent                              |
| ------------------------------ | -------------------------------------------------- |
| `spec.source` + `spec.compose` | `kind: Deployment` (pods built from compose)       |
| `spec.ingress`                 | `kind: Ingress` (one rule per entry, TLS preset)   |
| `spec.envFrom[].secretRef`     | `envFrom: [{ secretRef: { name: ... } }]`          |
| `spec.databases`               | per-app database and role + Secret on a shared instance |
| `spec.strategy`                | `strategy: RollingUpdate`, but blue-green          |
| `spec.migrate`                 | a migration Job run before the rollout             |

Unknown fields are ignored, so a manifest written for a newer nuk won't take a live deploy down on an older one. Fields that gate access are the opposite: they are closed sets, and anything unrecognised is refused.

## What `nuk apply` does

1. Clones `spec.source.repo` (or fast-forwards it) into `/opt/nuklaut/deployments/<name>/repo`. With `--repo-path <dir>` it mirrors an existing checkout instead. That is what the CI runner does, so the controller needs no git credentials.
2. If `spec.databases` is set, provisions the Postgres role and database and/or the Redis ACL user, and writes the URLs to `/opt/nuklaut/secrets/<name>-db.env` (mode 600).
3. Writes `compose.override.yml` next to the repo: joins each ingress service to the external `edge` network, and to the private `data` network when a database was requested.
4. Writes `/opt/nuklaut/traefik/dynamic/<name>.yml`: one router and service per ingress entry, TLS through the `letsencrypt` resolver.
5. Copies the manifest to `/opt/nuklaut/deployments/<name>/manifest.yml`.
6. Runs `docker compose -p <name> ... up -d`. It does not pass `--pull`: images are expected to be in the shared daemon already, pulled by your deploy workflow.

It also records the release (repo, branch, commit, image digest) in a history that `nuk rollback` reads.

If the ingress names exactly one host, every wired service also gets `NUK_PUBLIC_URL=https://<host>` in its container environment. That is the app's fixed public origin, useful for OAuth callbacks, emails sent outside a request, and origin allowlists. With zero or several hosts nuk sets nothing and says so. It never guesses.

### Secrets

An `envFrom` entry takes exactly one of:

* `secretRef`: an existing env file on the host, injected into the container environment of each ingress service and used for `${VAR}` interpolation.
* `sopsFile`: a tree-relative `*.enc.env` file, decrypted at apply time with the tenant's age key (`/etc/nuklaut/age.d/<tenant>.key`) into `/run/nuklaut/secrets` (a tmpfs). A missing file or key refuses the apply.

### Auth on a route

`auth: basic` puts HTTP Basic Auth in front of a route. `auth: oauth` puts the org's OAuth gate there. Both resolve to whatever the org's auth facility provides, and nuk refuses to publish a route whose gate no facility provides. Name the gate, not the implementation: `auth: authentik` is an error that tells you to write `auth: oauth`.

## Databases

`spec.databases` provisions per-app access on a shared data stack: one `nuk-postgres` (with pgvector) and one `nuk-redis`, on a private `data` network that Traefik never touches.

* A Postgres role and database named after the app, with the `vector` extension enabled and `CONNECT` revoked from everyone else. The URL arrives as `DATABASE_URL`.
* A Redis ACL user limited to keys and channels prefixed `<app>:`, with dangerous commands removed (no `FLUSHALL` on a shared instance). The URL arrives as `REDIS_URL`.
* Passwords are generated once and kept in `/opt/nuklaut/secrets/<app>-db.env`. Re-applying reuses them.
* `postgres: { driver: asyncpg }` gives you `postgresql+asyncpg://...`. Plain `true` gives a libpq `postgresql://` URL.
* `postgres: { scratch: true }` adds a second database, `<app>-scratch`, owned by the same role and exposed as `SCRATCH_DATABASE_URL`. It is for the app's own staging work (a restore drill, a throwaway import). nuk creates it and then never writes to it, empties it, or reads it. Postgres truncates identifiers at 63 bytes, so if `<app>-scratch` doesn't fit, nuk refuses the apply instead of letting the server rename it.

By default the URLs go to your ingress services. `attachTo: [web, worker]` picks the services explicitly (handy for a worker with no ingress), and `attachAll: true` injects into every compose service.

Provisioning runs `docker exec` against the shared containers, so database superuser secrets never show up in a host process's arguments.

Data is hard to get back, so nuk is careful with it:

```console
$ nuk delete my-app            # tears the app down, KEEPS the database
$ nuk db ls                    # managed databases, flagging retained ones with no deployment
$ nuk delete my-app --purge    # also drops the database, role and Redis user (DESTROYS DATA)
$ nuk db purge my-app          # same, for an app that is already deleted
```

Turning `scratch` off later does not drop the scratch database either. Only `--purge` and `nuk db purge` destroy data.

## Rollouts

### Blue-green

```yaml
spec:
  strategy:
    type: blue-green
    health: { service: backend, path: /healthz, port: 8000, timeout: 120, interval: 2 }
    drain: 30            # seconds before the old colour goes away; default 30
    keepPrevious: true   # keep the old colour running for instant rollback; default true
```

nuk brings the idle colour up, waits for its health probe to pass, flips the router to it, then drains the previous colour. If the probe never passes, the old colour keeps serving.

### Migrations

A one-shot migration runs before the idle colour comes up:

```yaml
spec:
  migrate: { service: backend, command: "alembic upgrade head", timeout: 300 }
```

`service` is a compose service whose image, environment and network nuk reuses. On a blue-green app, give the colour-agnostic name: nuk appends the idle colour and enables its profile, exactly as it does for `strategy.health.service`. `command` is split with `shlex` and passed as argv, so shell syntax doesn't apply. Wrap compound commands as `sh -c '...'`.

nuk runs `docker compose ... run --rm --no-deps <service> <command>`. A non-zero exit or a timeout fails the deploy while the previous colour keeps serving. The migration runs only when the configured image of the migrate service changes (the converge loop re-applies every cycle, and an unchanged stack must not migrate again), and never on a rollback.

**Migrations must be expand/contract.** The old colour keeps serving while the migration runs.

### Digest-pinned images

A compose image may be pinned by digest (`ghcr.io/org/app/backend@sha256:...`, no tag), which makes an env-file bump the only way to release. nuk supports it throughout:

* **Migrate gate**: a digest ref is its own identity, so no local image lookup is needed. A tag ref is resolved through the daemon's `RepoDigests`.
* **Provenance**: Compose reports an empty tag for a digest-pinned container, so nuk resolves the digest by image ID. The recorded row is the deployment's primary service (the `health.service` of the active colour, else the first ingress service).
* **Rollback**: only `keepPrevious: true` makes the colour flip a real rollback. A drained colour has no container left to preserve, so it is created fresh from the current tree, which is exactly the release you are trying to escape.

### Rolling back

```console
$ nuk rollback my-app --list    # print the release history, apply nothing
$ nuk rollback my-app           # the previous release
$ nuk rollback my-app --to 3    # a specific entry (negative indices count from the end)
```

Rollback is a human decision. The converge loop never rolls back on its own, because an automatic rollback in the middle of an incident would fight whoever is fixing it.

* On a blue-green app, a plain `nuk rollback` flips the router back to the previous colour, after bringing it up and health-gating it. Nothing is pulled.
* Otherwise nuk re-applies the recorded release from its commit and image digest. The entry is appended to the history as the new head, like a Helm revision.
* The history lives in `/var/lib/nuk/releases/<name>.jsonl` and keeps the last 20 releases. Re-applying the same release refreshes its timestamp instead of adding a line, so indices don't shift under you while you look.
* Facilities roll back by tag, not by `nuk rollback`.

## Commands

```console
$ nuk apply <manifest>            # create or update (provisions requested databases)
$ nuk list                        # deployments, container state, hosts (aliases: get, ls)
$ nuk status <name>               # one app: containers, ingress, databases, source
$ nuk status                      # org-wide overview, as JSON
$ nuk logs <name>                 # docker compose logs -f
$ nuk rollout <name>              # git pull + compose pull + up -d
$ nuk rollback <name>             # see "Rolling back"
$ nuk delete <name> [--purge]     # see "Databases"
$ nuk db ls | purge <name>        # managed databases
$ nuk converge                    # apply everything declared by this host's sources
$ nuk update [--check | --to <tag>]
$ nuk org resolve|validate|get|show   # org manifests; run anywhere
```

The org-wide `nuk status` takes `--json` (pretty-print), `--all --org-file <path>` (compare against the declared org manifest), and `--probe` (a best-effort HTTPS probe of every ingress host, off by default).

### Shell completion

Tab completion covers subcommands, flags, and your live deployment names (`nuk status <TAB>`, `nuk db purge <TAB>`):

```console
$ nuk --install-completion
```

Start a new shell afterwards. `nuk --show-completion` prints the script instead, if you'd rather install it by hand.

## Running a fleet

Everything above works on one box with `nuk apply`. For a fleet, you don't run `apply` by hand: each host runs `nuk converge`, and your git repos are the source of truth.

### Converge

```console
$ nuk converge
```

`converge` reads `/etc/nuklaut/sources.yml`, which lists the repos this host follows:

```yaml
sources:
  - name: platform                       # exactly one source applies `facilities`
    repo: git@github.com:acme/infra.git
    deploy_key: /etc/nuklaut/deploy-keys/platform
    apply: [facilities]
  - name: acme-web                       # every other source is a tenant
    repo: git@github.com:acme/web.git
    deploy_key: /etc/nuklaut/deploy-keys/acme-web
    apply: [deployments, databases]
    verify: signed                       # or: none
```

For each source, nuk fetches the repo with its own read-only deploy key, finds the newest verifying `v*` tag, and applies that tree: `facilities/` and `deployments/*.yml` from the tag, never from a working tree. The platform source goes first. One source refusing never stops another, except that tenants build on the platform tree, so they are refused when the platform didn't verify.

It's meant to be run on a timer and poked after a release, with a slow liveness floor so a single lost poke can't leave a host stale forever. Runs are serialized by a lock; a run that finds the lock held exits 0 and skips the cycle. Results land in `/var/lib/nuk/converge-status.json` on every exit path. The exit code is 1 if any source was refused.

The loop never removes anything. Apps no source declares any more are reported as warnings, and retiring one is an explicit `nuk delete <name>`.

Every source's repo needs a `main` branch: nuk fetches it alongside the tags.

### Trust

* **`verify: signed`** (the default): the applied tag must be SSH-signed by a key in `/etc/nuklaut/allowed_signers.d/<name>`, and that file must exist. nuk passes the trust anchor to `git verify-tag` on the command line and never reads it from the repo, because a repo that names its own trust anchor doesn't have one.
* **`verify: none`**: no signature check. nuk applies the newest `v*` tag that is an ancestor of `origin/main`, so this is no more powerful than push access to `main`. The cycle log line ends in `UNVERIFIED`.
* The platform source must be `signed`. An unsigned platform tag would let anyone who can push there decide what every host applies.
* **No downgrades**: nuk remembers the commit it last applied for each source and refuses a tag that isn't its descendant. Deleting newer tags can't walk the fleet backwards. An ambiguous history (rewritten, garbage-collected) is treated the same way, and asks for a human.
* **No silent skips**: a newer `v*` tag that fails verification is reported on stderr with git's reason. A release signed with the wrong key shouldn't just quietly never land.
* A single tag nobody can verify can't block the loop: nuk checks every candidate, not only the newest.
* `spec.source.unsigned: true` opts a single non-prod deployment into the branch head instead of a signed tag. Production deployments leave it off.

Each source's mode is recorded as `verify` in `converge-status.json`.

### Facilities and placement

A `kind: Facility` is a `Deployment` plus `spec.provides`: it declares what it hands out to apps (a route decoration like an auth middleware chain, or an environment binding like `postgres`), and `spec.health.containers` to say what "up" means. Apps consume capabilities by name, so `auth: oauth` works the same whichever implementation the org runs.

A facility can also use `spec.install` to put files from its payload directory (`facilities/<name>/`) into `/opt/nuklaut/traefik/dynamic/`:

```yaml
spec:
  install:
    - src: global.yml          # relative to the payload directory
      name: global.yml         # file name in traefik/dynamic/
      vars: { AUTH_BACKEND: "authentik-server:9000" }
      secretVars: { DASHBOARD_AUTH: /etc/nuklaut/secrets/dashboard-users }
```

`__TOKEN__`s are replaced in YAML values only (`DOMAIN` is the org's `platformDomain`), the result is re-parsed, and the file is swapped in atomically. nuk never overwrites a file it didn't write. To hand an existing one over, move it aside once (`mv global.yml global.yml.pre-nuk`).

`spec.placement` says which kind of host runs a manifest: `role` is one of `edge`, `data`, `app`, `hypervisor` or `all-in-one`, and `host` pins it to a named host when a role has several.

### The org manifest

`nuk org` reads an org's `nukorg/v1` manifest, `<org>/infra/nuklaut.org.yml`: the single declarative source for domains, hosts, DNS and TLS, secrets, auth, runners and mesh. Both the platform bootstrap and the deploy tooling read it. See [`examples/nuklaut.org.yml`](examples/nuklaut.org.yml) for a fully commented one.

```console
$ nuk org resolve [--repo-path .]   # the GitHub org of a repo's origin
$ nuk org validate <path>           # exit nonzero if the manifest is invalid
$ nuk org get <path> <dotted.key>   # one value, for scripts: facilities.auth
$ nuk org show <path>               # the validated manifest as normalized YAML
```

These run off the controller (your laptop, CI), so they skip the `/opt/nuklaut` check.

### A single host

One tenant on one VM (role `all-in-one`) doesn't need any of the fleet files:

* **Org manifest name**: the platform source may set `org_file: nuklaut.org.yml`. The default is `nuklaut.astrocloud.org.yml`. It lives in host configuration so a tag can't choose it, and it is refused on any non-platform source.
* **One host**: `hosts[].privateIp` is optional when the org has exactly one host, and required otherwise. A deployment placed on `app`, `data` or `edge` runs on the `all-in-one` host, with its router written locally.

## Deploying from CI

In the astrojones org, repos deploy themselves with the reusable `nuk-deploy.yml` workflow from `astrojones/.github`, on the org's self-hosted runner. The manifest lives at `deployment.yml` in the repo root (nuk falls back to `.nuklaut/deployment.yml` if it's absent), the image goes to `ghcr.io/<owner>/<repo>`, and per-app secrets live at `/opt/nuklaut/secrets/<repo>.env`.

## Development

```console
$ uv sync
$ uv run pytest            # unit tests; no controller or Docker needed
$ uv run ruff check        # lint
$ uv run ty check          # type-check
```

The integration tier provisions real Postgres and Redis containers, so it is opt-in and needs Docker:

```console
$ NUK_INTEGRATION=1 POSTGRES_PASSWORD=... REDIS_ADMIN_PASSWORD=... uv run pytest -m integration
```


The code is a flat package in `nuk/`, one module per concern: `models.py` (the manifest), `ingress.py` and `compose.py` (rendering), `databases.py`, `rollout.py`, `converge.py`, `sources.py` (signed-tag trust), `org.py`, `facility.py`, `provenance.py`, `status.py`, and `cli.py` for the Typer commands.

The render functions are dict-in, dict-out, because their YAML output is a wire contract with Traefik and Compose. Pydantic validates at the edges: when a manifest is loaded, and in the command layer. That also keeps the tests fast. Most of them run entirely in-process.

Design notes and plans live in [`docs/superpowers/`](docs/superpowers/).

### Releasing

You don't. Every push to `main` runs `.github/workflows/release.yml`, which derives the next version from [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, ...), stamps it into `nuk/__init__.py` and `pyproject.toml`, re-locks `uv.lock`, and creates the tag and GitHub release. Nothing is built or uploaded: `nuk update` and `uv tool install --from git+...` install straight from the tagged source.

## License

This project is licensed under the terms of the MIT license.
