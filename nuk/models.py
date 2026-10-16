#!/usr/bin/env python3
"""Pydantic models for a nuk/v1 manifest: spec, facility, deployment, ...

Extracted from `nuk/__init__` during the module split. `nuk/__init__`
re-exports the public names (and `load`) for backwards compatibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal

if TYPE_CHECKING:
    from pathlib import Path

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from nuk.util import die

# --- manifest models ----------------------------------------------------------
# Typed view of the nuk/v1 manifest. Validation happens once, at the load()
# boundary; the render/compose functions below stay dict-in/dict-out because
# their YAML output is an external wire contract (Traefik + docker-compose) that
# must not shift. extra="ignore" (pydantic's default) so a real manifest with a
# field nuk does not model still validates rather than killing a live deploy.


class _NullTolerant(BaseModel):
    """Base for manifest blocks that treat a null-valued YAML key as absent.

    A bare YAML key (`ingress:`) parses to None; the original CLI defended every
    optional field with `or []`/`or {}`, so such manifests are valid in the wild
    (workflow deploys ship bare `source:`). Dropping None-valued keys before
    validation lets the field defaults engage instead of failing a strongly-typed
    field — keeping the fields non-Optional at the boundary.
    """

    @model_validator(mode="before")
    @classmethod
    def _drop_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v is not None}
        return data


class Source(BaseModel):
    """`spec.source` — the git repo and branch to deploy."""

    repo: str | None = None
    branch: str = "main"
    # Opt into deploying the branch head without a signed `v*` tag — for
    # non-prod/test deployments. Prod deployments leave this False and require
    # a signed tag.
    unsigned: bool = False


class Compose(BaseModel):
    """`spec.compose` — path to the compose file inside the repo."""

    file: str = "docker-compose.yml"

    @model_validator(mode="before")
    @classmethod
    def _coerce_string(cls, data: object) -> object:
        """Allow passing compose as a string directly (converted to {file: ...})."""
        if isinstance(data, str):
            return {"file": data}
        return data


class Ingress(BaseModel):
    """One `spec.ingress[]` entry — a single Traefik router/service."""

    model_config = ConfigDict(populate_by_name=True)

    host: str
    service: str | None = None
    port: int | None = None
    # "<ip>:<port>" backend outside this host's docker "edge" network — e.g. a
    # libvirt VM on a separate hypervisor host, reached over the private
    # vswitch/cloud-network. Mutually exclusive with service/port.
    address: str | None = None
    path: str | None = None
    strip_prefix: bool = Field(default=False, alias="stripPrefix")
    priority: int | None = None
    www: bool = False
    # When this app runs on a non-edge host (worker), its container port is published on
    # the private IP for the edge Traefik to reach it. hostPort overrides the HOST side of
    # that bind (default = port), so two worker apps sharing a container port don't collide
    # on the host. Ignored on an edge/all-in-one host (no publish). Finding 6.
    host_port: int | None = Field(default=None, alias="hostPort")
    # Which gate to put in front of this route. Since authentik and oauth2-proxy were retired
    # `basic` is the only value, and it resolves through the route capability of the same name.
    # This MUST stay a closed set: an unknown value used to render a router with NO auth
    # middleware and NO error, an authentication control failing OPEN on a typo. A retired value
    # (`oauth`, `authentik`) is now a load-time ValidationError.
    auth: Literal["basic"] | None = None

    @model_validator(mode="after")
    def _check_backend(self) -> Ingress:
        """Exactly one backend: `address` (remote) or `service`+`port` (local).

        Raises:
            ValueError: If both or neither backend forms are given.
        """
        if self.address and (self.service is not None or self.port is not None):
            msg = "ingress: set either `address` or `service`+`port`, not both"
            raise ValueError(msg)
        if not self.address and (self.service is None or self.port is None):
            msg = "ingress: `service` and `port` are required unless `address` is set"
            raise ValueError(msg)
        return self


class EnvFrom(BaseModel):
    """One `spec.envFrom[]` entry — a secret env-file reference."""

    model_config = ConfigDict(populate_by_name=True)

    secret_ref: str | None = Field(default=None, alias="secretRef")


class Postgres(BaseModel):
    """`spec.databases.postgres` object form — picks the URL scheme driver."""

    driver: str | None = None


class Databases(_NullTolerant):
    """`spec.databases` — opt-in per-app postgres/redis on the shared stack.

    By default the generated DATABASE_URL / REDIS_URL are injected into the
    ingress service(s). `attachTo` overrides that target list (e.g. to reach a
    worker that has no ingress); `attachAll` injects into every compose service.
    """

    model_config = ConfigDict(populate_by_name=True)

    postgres: bool | Postgres = False
    redis: bool = False
    attach_to: list[str] = Field(default=[], alias="attachTo")
    attach_all: bool = Field(default=False, alias="attachAll")

    @property
    def wants_postgres(self) -> bool:
        """Whether postgres is requested; the object form `{}` is not (a raw `{}` was falsy)."""
        if isinstance(self.postgres, Postgres):
            return bool(self.postgres.model_fields_set)
        return self.postgres

    @property
    def wants_redis(self) -> bool:
        """Whether redis is requested."""
        return self.redis

    @property
    def postgres_driver(self) -> str | None:
        """The URL-scheme driver of the object form; bare `true` has none."""
        return self.postgres.driver if isinstance(self.postgres, Postgres) else None


# The host roles a placement can target and an org host can carry (spec §3.1).
Role = Literal["edge", "data", "app", "hypervisor", "all-in-one"]


class Placement(BaseModel):
    """`spec.placement` — the role whose hosts run this manifest's containers.

    `host` optionally pins a manifest to ONE named host of that role, for a role
    that has several hosts (spec §13's `selector:` seam). Absent it, the role must
    resolve to a single host.

    Shared by both kinds (spec §4.2). Replaces the two implicit placement
    mechanisms it supersedes: "whichever host someone ran `nuk apply` on", and
    converge.sh's retired APPS environment variable.
    """

    role: Role
    host: str | None = None


class Health(_NullTolerant):
    """`spec.health` — how a facility proves it is actually up.

    Vocabulary is git-derived and fleet-wide; health is same-host (spec §5.3).
    Only the host whose `placement.role` owns a facility can check it.
    """

    containers: list[str] = []


class RouteProvide(BaseModel):
    """`spec.provides.route` — a stateless decoration a router can opt into.

    `capability` is what the facility HANDS OUT; a Deployment consumes it by
    naming it in a field (`ingress[].auth: basic` → capability `basic`).
    `middlewares` are applied in declaration order, outer→inner.
    """

    capability: str
    middlewares: list[str] = []


class EnvProvide(BaseModel):
    """`spec.provides.env` — a stateful binding handed to an app as env vars.

    `bind` names the wire protocol a capability is offered on. `postgres`
    is a SQL bind to a provisioned cluster; `otlp` is an OTLP ingest
    endpoint (facility `logging`, spec §14.1) — declared for the vocabulary
    only, since no manifest field consumes `logs` (§14.3) and no code
    branches on the value.
    """

    capability: str
    bind: Literal["postgres", "otlp"]


class Provides(_NullTolerant):
    """`spec.provides` — what a Facility hands out.

    The whole of `Facility ≡ Deployment + spec.provides`.
    """

    route: RouteProvide | None = None
    env: EnvProvide | None = None


class StrategyHealth(_NullTolerant):
    """`spec.strategy.health` — the blue-green readiness probe for one service.

    Distinct from the facility `Health` (`spec.health.containers`): this one
    names a compose service and the HTTP path that proves its idle colour is up.
    """

    model_config = ConfigDict(populate_by_name=True)

    service: str
    path: str
    port: int | None = None
    timeout: int = 120
    interval: float = 2.0


class Strategy(_NullTolerant):
    """`spec.strategy` — how a Deployment rolls out its containers.

    `blue-green` brings the idle colour up, gates on `health`, flips the
    app-host router to it, then drains the previous colour — unless
    `keepPrevious` keeps it running for an instant rollback.
    """

    model_config = ConfigDict(populate_by_name=True)

    type: Literal["blue-green"]
    health: StrategyHealth
    drain: int = 30
    keep_previous: bool = Field(default=True, alias="keepPrevious")


class Migrate(_NullTolerant):
    """`spec.migrate` — a one-shot schema migration run before the rollout.

    nuk owns *when* (before the idle colour comes up, gated to a new rollout);
    the app declares *how*: a compose service whose image/env nuk reuses, and
    the command to run in it. `command` is split with `shlex.split` and passed
    as argv — shell syntax (`&&`, pipes, globs, quotes beyond grouping) does not
    apply, so wrap a compound command as `sh -c '…'`.
    """

    model_config = ConfigDict(populate_by_name=True)

    service: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    command: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    timeout: int = Field(default=300, gt=0)


class Spec(_NullTolerant):
    """The manifest `spec` block."""

    model_config = ConfigDict(populate_by_name=True)

    source: Source = Source()
    compose: Compose = Compose()
    ingress: list[Ingress] = []
    env_from: list[EnvFrom] = Field(default=[], alias="envFrom")
    databases: Databases = Databases()
    placement: Placement | None = None
    strategy: Strategy | None = None
    migrate: Migrate | None = None


class Metadata(BaseModel):
    """The manifest `metadata` block."""

    name: str


class FacilitySpec(Spec):
    """A Facility's `spec` — a Deployment's spec plus what it hands out.

    `Facility ≡ Deployment + spec.provides` (spec §4.2). `source`, `compose`,
    `ingress`, `databases`, `placement` are inherited unchanged.
    """

    provides: Provides = Provides()
    health: Health = Health()


class Manifest(_NullTolerant):
    """The fields every nuk/v1 document shares, whatever its kind."""

    model_config = ConfigDict(populate_by_name=True)

    api_version: Literal["nuk/v1"] = Field(alias="apiVersion")
    metadata: Metadata


class Deployment(Manifest):
    """An app stack: containers, ingress, optional databases."""

    kind: Literal["Deployment"]
    spec: Spec = Spec()


class Facility(Manifest):
    """A platform service that additionally declares what it provides."""

    kind: Literal["Facility"]
    spec: FacilitySpec = FacilitySpec()


# One document family, one apiVersion, one union — discriminated on `kind` so a
# typo in `kind` is a validation error rather than a silently-skipped document.
AnyManifest = Annotated[Deployment | Facility, Field(discriminator="kind")]
_MANIFEST_ADAPTER = TypeAdapter(AnyManifest)


def load(path: Path) -> Deployment | Facility:
    """Parse and validate a manifest file into a `Deployment` or a `Facility`.

    Args:
        path: Path to the manifest YAML.

    Returns:
        The validated manifest.

    Raises:
        NukError: If the document is not a valid nuk/v1 Deployment or Facility.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    try:
        manifest = _MANIFEST_ADAPTER.validate_python(raw)
    except ValidationError:
        die(f"{path}: not a nuk/v1 Deployment or Facility")
    return manifest
