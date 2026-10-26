#!/usr/bin/env python3
"""Wire records for nuk: converge status, manifest results, source blocks.

These are the on-disk / JSON wire representations. Moved out of `nuk/__init__`
during the module split; `nuk/__init__` re-exports them for backwards compat.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Self

from nuk.util import _str_list, _str_or_none

# The return type of every record's `to_wire()`: exactly what json.dumps / yaml.safe_dump take.
type Json = dict[str, Json] | list[Json] | str | int | float | bool | None

# Converge status (JSON; written each cycle and read back by `nuk status` / drift.sh)

type ManifestKind = Literal["Facility", "Deployment", "Database"]
type ManifestOutcome = Literal["ok", "failed", "refused"]


@dataclass(frozen=True)
class ManifestResult:
    """One applied manifest's outcome (spec §7.6)."""

    name: str
    kind: ManifestKind
    result: ManifestOutcome = "ok"
    error: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """All four keys, always; `error` is an explicit null on success."""
        return {"name": self.name, "kind": self.kind, "result": self.result, "error": self.error}

    @classmethod
    def from_wire(cls, obj: object) -> Self | None:
        """None for anything that is not a well-formed entry."""
        if not isinstance(obj, dict):
            return None
        name, error = obj.get("name"), obj.get("error")
        if not isinstance(name, str) or not (error is None or isinstance(error, str)):
            return None
        match obj.get("kind"), obj.get("result"):
            case ("Facility" | "Deployment" | "Database") as kind, (
                "ok" | "failed" | "refused"
            ) as result:
                return cls(name, kind, result, error)
        return None


@dataclass(frozen=True)
class LoggingStatus:
    """The logging pipeline's own health; info-only (spec §14.3)."""

    healthy: bool
    detail: str

    def to_wire(self) -> dict[str, Json]:
        """Both keys, always."""
        return {"healthy": self.healthy, "detail": self.detail}

    @classmethod
    def from_wire(cls, obj: object) -> Self | None:
        """None for anything that is not a well-formed block."""
        if not isinstance(obj, dict):
            return None
        healthy, detail = obj.get("healthy"), obj.get("detail")
        if isinstance(healthy, bool) and isinstance(detail, str):
            return cls(healthy, detail)
        return None


# Not frozen: _prepare_source/_apply_source/_refuse fill the block in place, and the cycle
# holds the same object in `blocks` while they do.
@dataclass
class SourceBlock:
    """One source's block in the converge status."""

    result: Literal["ok", "refused"] = "ok"
    error: str | None = None
    tag: str | None = None
    commit: str | None = None
    apply: list[str] = field(default_factory=list)
    manifests: list[ManifestResult] = field(default_factory=list)
    rendered: list[str] = field(default_factory=list)
    refused_routes: list[str] = field(default_factory=list)
    verify: Literal["signed", "none"] = "signed"

    def to_wire(self) -> dict[str, Json]:
        """All nine keys, always, in this order."""
        return {
            "result": self.result,
            "error": self.error,
            "tag": self.tag,
            "commit": self.commit,
            "apply": [*self.apply],
            "manifests": [m.to_wire() for m in self.manifests],
            "rendered": [*self.rendered],
            "refusedRoutes": [*self.refused_routes],
            "verify": self.verify,
        }

    @classmethod
    def from_wire(cls, obj: object) -> Self | None:
        """None for a non-conforming block; missing lists read empty, missing verify as signed."""
        if not isinstance(obj, dict):
            return None
        raw_manifests = obj.get("manifests")
        manifests = [
            ManifestResult.from_wire(m)
            for m in (raw_manifests if isinstance(raw_manifests, list) else [])
        ]
        error = obj.get("error")
        if None in manifests or not (error is None or isinstance(error, str)):
            return None
        match obj.get("result"), obj.get("verify", "signed"):
            case ("ok" | "refused" as result, "signed" | "none" as verify):
                return cls(
                    result,
                    error,
                    _str_or_none(obj.get("tag")),
                    _str_or_none(obj.get("commit")),
                    _str_list(obj.get("apply")),
                    [m for m in manifests if m is not None],
                    _str_list(obj.get("rendered")),
                    _str_list(obj.get("refusedRoutes")),
                    verify,
                )
        return None


@dataclass(frozen=True)
class ConvergeStatus:
    """`converge-status.json`: the last cycle's outcome."""

    role: str
    tenant: str | None
    applied_at: str
    reap_warnings: list[str]
    sources: dict[str, SourceBlock]
    logging: LoggingStatus | None = None
    error: str | None = None

    def to_wire(self) -> dict[str, Json]:
        """`logging` and `error` are absent (never null) unless set."""
        out: dict[str, Json] = {
            "role": self.role,
            "tenant": self.tenant,
            "appliedAt": self.applied_at,
            "reapWarnings": [*self.reap_warnings],
            "sources": {k: v.to_wire() for k, v in self.sources.items()},
        }
        if self.logging is not None:
            out["logging"] = self.logging.to_wire()
        if self.error is not None:
            out["error"] = self.error
        return out

    @classmethod
    def from_wire(cls, obj: object) -> Self | None:
        """None when the document is not a converge status (the reader treats it as absent)."""
        if not isinstance(obj, dict):
            return None
        role, raw_sources = obj.get("role"), obj.get("sources")
        if not isinstance(role, str) or not isinstance(raw_sources, dict):
            return None
        sources = {str(k): SourceBlock.from_wire(v) for k, v in raw_sources.items()}
        parsed = {k: b for k, b in sources.items() if b is not None}
        if len(parsed) != len(sources):
            return None
        return cls(
            role,
            _str_or_none(obj.get("tenant")),
            _str_or_none(obj.get("appliedAt")) or "",
            _str_list(obj.get("reapWarnings")),
            parsed,
            LoggingStatus.from_wire(obj.get("logging")),
            _str_or_none(obj.get("error")),
        )
