-- Durable transfer lifecycle accounting. Safe for installations that already
-- have the phase 5/6 transfer tables, and harmless when they are absent.
ALTER TABLE IF EXISTS tenant_quotas
  ADD COLUMN IF NOT EXISTS pending_upload_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE IF EXISTS guest_dropbox_uploads
  ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ;
ALTER TABLE IF EXISTS guest_dropbox_uploads
  ADD COLUMN IF NOT EXISTS reconciliation_state VARCHAR(32) NOT NULL DEFAULT 'staged';
CREATE INDEX IF NOT EXISTS ix_guest_dropbox_uploads_reconciliation_state
  ON guest_dropbox_uploads (reconciliation_state);
