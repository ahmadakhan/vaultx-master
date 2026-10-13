from __future__ import annotations

import hashlib

from app.core.recovery import canonical_json, verify_manifest
from app.models import LegalHold


def test_manifest_digest_verification_detects_mutation() -> None:
    payload = {"format": "vaultx-backup-manifest-v1", "objects": []}
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    assert verify_manifest({"manifest_sha256": digest, "manifest_json": payload}) == (True, digest)
    payload["objects"].append({"id": "unexpected"})
    assert verify_manifest({"manifest_sha256": digest, "manifest_json": payload})[0] is False


def test_legal_hold_defaults_to_active() -> None:
    hold = LegalHold(subject="subject-1", reason="preservation request", active=True)
    assert hold.active is True
