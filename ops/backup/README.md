# Backup and restore drill

Use a separately provisioned PostgreSQL database. This script refuses to use
the application database by default and verifies the database dump hash before
loading it.

```sh
chmod +x ops/backup/restore-drill.sh
DUMP_FILE=/restore/database.dump \
RESTORE_DATABASE_URL=postgresql://restore_user:secret@restore-db/vaultx_restore \
EXPECTED_SHA256=<database-object-sha256> \
ops/backup/restore-drill.sh
```

Record UTC start/end times, restored row counts, storage-object hashes,
successful authentication, a known-file download, audit-chain verification,
and operator signoff. The script only proves database loading; it does not
claim a complete recovery drill by itself.
