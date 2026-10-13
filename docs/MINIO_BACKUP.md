# MinIO backup and restore

VaultX can archive the PostgreSQL custom-format dump, ciphertext storage, and
a SHA-256 manifest to a self-hosted S3-compatible MinIO bucket. Credentials
are supplied only through environment/secrets; no keys belong in this repo.

## Bootstrap

Set `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `MINIO_BACKUP_ACCESS_KEY`, and
`MINIO_BACKUP_SECRET_KEY` externally, then start Compose. The backup adapter
creates `BACKUP_S3_BUCKET` with Object Lock and applies COMPLIANCE retention.
It fails closed if Object Lock configuration is rejected.

Run a backup from the backend environment:

```bash
python -c 'from app.core.backup import run_backup; print(run_backup())'
```

Use `run_backup(dry_run=True)` to enumerate the pg_dump and storage objects
without contacting PostgreSQL or MinIO. For scheduled execution, set
`BACKUP_ENABLED=true`; the Compose `backup-worker` runs the archive and audit
outbox delivery every `BACKUP_INTERVAL_MINUTES` (default 1440). Failed uploads
remain pending and are retried on the next cycle.

## Restore verification

Download a database object into an isolated PostgreSQL instance and run:

```python
from app.core.backup import verify_restore
print(verify_restore(dump_file="/restore/database.dump", restore_db="postgresql://..."))
```

`verified: true` is emitted only after `pg_restore --exit-on-error` actually
returns zero. A dry run reports `verified: false` and never claims recovery.
Ciphertext hashes in the manifest must also be checked before switching the
application to the restored storage volume.

Audit outbox delivery uses immutable keys under `audit-outbox/`; the adapter
sets COMPLIANCE Object Lock on every object and includes the event hash in its
key, making retries idempotent without overwriting evidence.
