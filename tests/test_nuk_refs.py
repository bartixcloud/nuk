"""spec.source.unsigned — a Deployment opting into deploying an unsigned branch head.

The first task of the per-deployment-ref feature: a non-prod/test deployment can
declare that it deploys the branch head without a signed `v*` tag. This task adds
the model field only; fetch/apply behaviour lands in later tasks.

    uv run pytest tests/test_nuk_refs.py
"""

from __future__ import annotations

import nuk
import yaml


def _manifest(tmp_path, source: dict) -> nuk.Deployment | nuk.Facility:
    path = tmp_path / "deployment.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "apiVersion": "nuk/v1",
                "kind": "Deployment",
                "metadata": {"name": "app"},
                "spec": {"source": source},
            }
        ),
        encoding="utf-8",
    )
    return nuk.load(path)


def test_source_unsigned_true_parses(tmp_path):
    manifest = _manifest(tmp_path, {"repo": "https://example.com/app.git", "unsigned": True})
    assert manifest.spec.source.unsigned is True


def test_source_unsigned_defaults_false(tmp_path):
    manifest = _manifest(tmp_path, {"repo": "https://example.com/app.git"})
    assert manifest.spec.source.unsigned is False


def test_source_unsigned_round_trips():
    source = nuk.Source(repo="r", unsigned=True)
    assert nuk.Source.model_validate(source.model_dump()).unsigned is True
