# Recovery and governance baseline

VaultX records a production baseline without claiming that an external backup
provider is configured. `RECOVERY_RPO_MINUTES`, `RECOVERY_RTO_MINUTES`, and
optional `DATA_RESIDENCY_REGION` are explicit configuration inputs. Administrators
can publish policy evidence through `/admin/governance/recovery`; evidence is
stored as an assertion with `verified: false` until an operator records a local
verification result.

## Recovery

`POST /admin/governance/recovery/manifest` creates a canonical JSON manifest of
database file metadata and stores its SHA-256 digest. The verify endpoint
recomputes the digest, while export returns the signed boundary payload for a
configured delivery adapter. `BackupSink` in `backend/app/core/recovery.py` is
the adapter interface; no cloud bucket, credentials, or remote endpoint is
embedded. The manifest is metadata-only and does not expose plaintext keys.

## Durable audit delivery

Every tamper-log append also inserts an immutable `audit_outbox` row containing
the event payload and digest. `/admin/governance/audit/outbox` exposes pending
rows for a separately operated exporter. Delivery is represented by a future
adapter boundary; the API does not mark rows delivered or imply external
durability. Tamper logs and outbox rows have no update/delete API.

## Retention, legal hold, export and erasure

Trash retention remains controlled by `TRASH_RETENTION_DAYS`. Legal holds are
admin-only, auditable, and block subject erasure while active. Hold release and
erasure are destructive operations protected by the admin dependency and MFA
through the existing admin router policy. Recovery manifest export is
admin-only and returns the canonical local payload. Residency is metadata and
must be enforced by the deployment's storage adapter and infrastructure.

All destructive requests emit hash-chained audit events; failures never turn a
successful destructive operation into an unaudited operation silently in the
request response path, and operators should monitor the audit outbox.
