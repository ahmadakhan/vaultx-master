"""Self-hosted, S3-compatible backup and recovery primitives.

The adapter is deliberately small and boto3-compatible: MinIO, Ceph RGW and
other S3 implementations can be used without putting credentials in source.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from app.core.recovery import canonical_json


class ObjectStore(Protocol):
    def put_object(self, **kwargs: Any) -> Any: ...
    def get_object(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class BackupResult:
    backup_id: str
    objects: tuple[str, ...]
    manifest_sha256: str
    dry_run: bool = False


class MinioBackupAdapter:
    """Uploads immutable backup objects and audit outbox events to MinIO."""

    def __init__(self, client: ObjectStore, bucket: str, *, retention_days: int = 30):
        self.client, self.bucket, self.retention_days = client, bucket, retention_days

    @classmethod
    def from_settings(cls) -> MinioBackupAdapter:
        from app.config import settings
        if not settings.backup_endpoint or not settings.backup_access_key or not settings.backup_secret_key:
            raise RuntimeError("BACKUP_S3_ENDPOINT, BACKUP_S3_ACCESS_KEY and BACKUP_S3_SECRET_KEY are required")
        import boto3
        client = boto3.client("s3", endpoint_url=settings.backup_endpoint,
                              aws_access_key_id=settings.backup_access_key,
                              aws_secret_access_key=settings.backup_secret_key,
                              region_name=settings.backup_region)
        return cls(client, settings.backup_bucket, retention_days=settings.backup_object_lock_days)

    def bootstrap_bucket(self) -> None:
        """Create an Object Lock bucket; never silently downgrade immutability."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except Exception:
            self.client.create_bucket(Bucket=self.bucket, ObjectLockEnabledForBucket=True)
        try:
            self.client.put_object_lock_configuration(
                Bucket=self.bucket,
                ObjectLockConfiguration={"ObjectLockEnabled": "Enabled", "Rule": {
                    "DefaultRetention": {"Mode": "COMPLIANCE", "Days": self.retention_days}
                }},
            )
        except Exception as exc:
            raise RuntimeError("MinIO bucket must support Object Lock") from exc

    def put_immutable(self, key: str, payload: bytes, *, content_type: str = "application/octet-stream") -> None:
        self.client.put_object(Bucket=self.bucket, Key=key, Body=payload, ContentType=content_type,
                               ObjectLockMode="COMPLIANCE",
                               ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=self.retention_days))

    def deliver_audit_outbox(self, event_id: int, payload: dict[str, Any]) -> str:
        key = f"audit-outbox/{event_id:020d}-{hashlib.sha256(canonical_json(payload)).hexdigest()}.json"
        self.put_immutable(key, canonical_json(payload), content_type="application/json")
        return key


def run_backup(*, pg_dump: str = "pg_dump", dry_run: bool = False,
               storage_dir: str | None = None, work_dir: str | None = None,
               adapter: MinioBackupAdapter | None = None) -> BackupResult:
    """Run pg_dump and upload DB, ciphertext blobs, and a signed-by-hash manifest."""
    from app.config import settings
    storage = Path(storage_dir or settings.storage_dir)
    work = Path(work_dir or settings.backup_work_dir)
    backup_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    db_file = work / f"{backup_id}.dump"
    objects: list[str] = []
    manifest: dict[str, Any] = {"format": "vaultx-minio-backup-v1", "backup_id": backup_id, "created_at": datetime.now(UTC).isoformat(), "objects": []}
    if dry_run:
        manifest["objects"].append({"key": f"{backup_id}/database.dump", "source": "pg_dump"})
        manifest["objects"].extend({"key": f"{backup_id}/storage/{p.relative_to(storage).as_posix()}", "source": str(p)} for p in storage.rglob("*") if p.is_file())
    else:
        if adapter is None:
            adapter = MinioBackupAdapter.from_settings()
        adapter.bootstrap_bucket()
        work.mkdir(parents=True, exist_ok=True)
        from app.config import settings as cfg
        env = os.environ.copy()
        env.update(PGHOST=cfg.db_host, PGPORT=str(cfg.db_port), PGDATABASE=cfg.db_name, PGUSER=cfg.db_user, PGPASSWORD=cfg.db_password)
        subprocess.run([pg_dump, "--format=custom", "--file", str(db_file)], env=env, check=True)
        adapter.put_immutable(f"{backup_id}/database.dump", db_file.read_bytes())
        objects.append(f"{backup_id}/database.dump")
        for path in storage.rglob("*"):
            if path.is_file():
                key = f"{backup_id}/storage/{path.relative_to(storage).as_posix()}"
                adapter.put_immutable(key, path.read_bytes())
                objects.append(key)
                manifest["objects"].append({"key": key, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size})
        manifest["objects"].insert(0, {"key": f"{backup_id}/database.dump", "sha256": hashlib.sha256(db_file.read_bytes()).hexdigest(), "size": db_file.stat().st_size})
    digest = hashlib.sha256(canonical_json(manifest)).hexdigest()
    if adapter and not dry_run:
        adapter.put_immutable(f"{backup_id}/manifest.json", canonical_json({"manifest": manifest, "sha256": digest}), content_type="application/json")
        objects.append(f"{backup_id}/manifest.json")
    return BackupResult(backup_id, tuple(objects), digest, dry_run)


def verify_restore(*, dump_file: str, restore_db: str, pg_restore: str = "pg_restore", dry_run: bool = False) -> dict[str, Any]:
    """Restore into an operator-provided isolated database and report the command result."""
    command = [pg_restore, "--clean", "--if-exists", "--exit-on-error", "--dbname", restore_db, dump_file]
    if dry_run:
        return {"verified": False, "dry_run": True, "command": command}
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return {"verified": completed.returncode == 0, "dry_run": False, "returncode": completed.returncode,
            "stderr": completed.stderr[-2000:]}
