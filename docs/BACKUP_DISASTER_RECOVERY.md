# Backup and disaster-recovery procedure

## Current implementation boundary

VaultX does **not** implement an automated backup scheduler, off-site backup
transport, retention manager, restore orchestrator, or disaster-recovery
service. The Compose file therefore does not advertise backup/DR feature flags.
Named Docker volumes provide persistence for a running deployment only; they do
not protect against host loss, operator error, or ransomware.

An operator must provide an external, access-controlled backup system and test
it. Until a completed restore test is recorded, backup coverage and recovery
objectives are **unverified**.

## Required backup set

Back up these items together, using a consistent snapshot where possible:

* PostgreSQL database (`pg_dump` in custom format or an equivalent managed
  snapshot).
* `/var/vaultx/storage` (encrypted file blobs).
* `/etc/vaultx/keys` and `/etc/vaultx/signing_keys` (required to preserve key
  continuity and historical audit verification).
* `/var/vaultx/logs` when audit log files are enabled.
* The exact application image/release identifier and deployment configuration,
  excluding secret values from tickets and logs.

Backups must be encrypted, access-controlled, versioned, and stored separately
from the production host. Never commit `.env` files or private keys to Git.

## Operator procedure (example, adapt to the approved backup system)

1. Quiesce writes or use the backup provider's transactionally consistent
   snapshot facility.
2. Export PostgreSQL and snapshot/copy each named volume listed above.
3. Record UTC timestamp, database WAL/transaction position if available,
   release image digest, and backup object identifiers.
4. Verify the backup objects can be read from a separate environment. A copy
   operation alone is not a restore test.
5. Apply the organization's retention and deletion policy only after a newer
   verified backup exists.

## Restore drill

1. Create an isolated project/network and restore the database and all required
   volumes; do not point a test frontend at production.
2. Start `migrate` and the backend using the restored signing keys.
3. Check `/health`, authenticate with a test account, download a known test
   file, and verify an audit chain using the restored key material.
4. Compare expected row counts, file hashes/ciphertext sizes, and audit-log
   continuity with the backup record.
5. Record start/end UTC times, data-loss window, failures, and operator signoff.

Do not claim a recovery time objective, recovery point objective, or successful
disaster recovery until this drill has passed on the target infrastructure.
