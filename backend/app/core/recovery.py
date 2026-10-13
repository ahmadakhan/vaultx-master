"""Local, verifiable recovery primitives and storage adapter boundary."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BackupManifest, File


class BackupSink(Protocol):
    """Optional destination for a manifest/blob exporter (no provider bundled)."""
    def put(self, name: str, payload: bytes) -> None: ...


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


async def build_manifest(db: AsyncSession, *, created_by: Any = None) -> BackupManifest:
    rows = (await db.execute(select(File).order_by(File.id))).scalars().all()
    objects = [{"id": str(row.id), "storage_path": row.storage_path, "size": row.file_size,
                "created_at": row.created_at.isoformat(), "deleted": row.deleted}
               for row in rows]
    payload = {"format": "vaultx-backup-manifest-v1", "created_at": datetime.now(UTC).isoformat(),
               "objects": objects}
    manifest = BackupManifest(created_by=created_by, object_count=len(objects),
                              manifest_sha256=hashlib.sha256(canonical_json(payload)).hexdigest(),
                              manifest_json=payload)
    db.add(manifest)
    await db.commit()
    await db.refresh(manifest)
    return manifest


def verify_manifest(manifest: BackupManifest | dict[str, Any]) -> tuple[bool, str]:
    expected = manifest.manifest_sha256 if isinstance(manifest, BackupManifest) else manifest["manifest_sha256"]
    payload = manifest.manifest_json if isinstance(manifest, BackupManifest) else manifest["manifest_json"]
    actual = hashlib.sha256(canonical_json(payload)).hexdigest()
    return actual == expected, actual


def export_manifest(manifest: BackupManifest) -> bytes:
    return canonical_json({"manifest_sha256": manifest.manifest_sha256,
                           "manifest_json": manifest.manifest_json})
