#!/usr/bin/env sh
set -eu

: "${DUMP_FILE:?Set DUMP_FILE to an isolated backup database.dump file}"
: "${RESTORE_DATABASE_URL:?Set RESTORE_DATABASE_URL to an isolated PostgreSQL database URL}"
: "${EXPECTED_SHA256:?Set EXPECTED_SHA256 to the manifest hash for DUMP_FILE}"

actual="$(sha256sum "$DUMP_FILE" | cut -d ' ' -f 1)"
test "$actual" = "$EXPECTED_SHA256" || {
  printf '%s\n' "backup hash mismatch: expected $EXPECTED_SHA256, got $actual" >&2
  exit 1
}

pg_restore --clean --if-exists --exit-on-error --dbname "$RESTORE_DATABASE_URL" "$DUMP_FILE"
printf '%s\n' "database restore succeeded; complete row-count, ciphertext, key, and audit checks before recording RTO/RPO evidence"
