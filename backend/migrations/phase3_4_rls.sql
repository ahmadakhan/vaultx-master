-- Phase 3/4 PostgreSQL foundation. Run as the migration owner, never as the
-- application role. The runtime role must not have BYPASSRLS.
-- Transfer tables are included here so a clean PostgreSQL deployment can apply
-- this migration before the application starts. Existing installations keep
-- their rows through CREATE TABLE IF NOT EXISTS.
CREATE TABLE IF NOT EXISTS upload_sessions (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  file_id uuid NOT NULL UNIQUE,
  total_bytes bigint NOT NULL,
  "offset" bigint NOT NULL DEFAULT 0,
  chunk_size integer NOT NULL,
  storage_path text,
  status text NOT NULL DEFAULT 'active',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS guest_dropboxes (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  capability_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  max_bytes bigint NOT NULL,
  used_bytes bigint NOT NULL DEFAULT 0,
  max_uploads integer NOT NULL DEFAULT 1,
  upload_count integer NOT NULL DEFAULT 0,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS guest_dropbox_uploads (
  id uuid PRIMARY KEY,
  dropbox_id uuid NOT NULL REFERENCES guest_dropboxes(id) ON DELETE CASCADE,
  tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE,
  storage_path text NOT NULL,
  size bigint NOT NULL DEFAULT 0,
  finalized boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'pending',
  file_id uuid UNIQUE,
  created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS tenant_id text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE files ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE index_entries ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE file_shares ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE shared_links ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE upload_sessions ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE guest_dropboxes ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE guest_dropbox_uploads ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE guest_dropbox_uploads ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'pending';
ALTER TABLE guest_dropbox_uploads ADD COLUMN IF NOT EXISTS file_id uuid;

-- Backfill rows where ownership is already unambiguous. Rows left NULL are
-- intentionally not exposed by the policies until an operator resolves them.
UPDATE files f SET tenant_id = u.tenant_id
FROM users u WHERE f.owner_id = u.id AND f.tenant_id IS NULL AND u.tenant_id IS NOT NULL;
UPDATE index_entries i SET tenant_id = u.tenant_id
FROM users u WHERE i.owner_id = u.id AND i.tenant_id IS NULL AND u.tenant_id IS NOT NULL;
UPDATE file_shares s SET tenant_id = u.tenant_id
FROM users u WHERE s.owner_user_id = u.id AND s.tenant_id IS NULL AND u.tenant_id IS NOT NULL;
UPDATE shared_links l SET tenant_id = f.tenant_id
FROM files f WHERE l.file_id = f.id AND l.tenant_id IS NULL AND f.tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_files_tenant_id ON files (tenant_id);
CREATE INDEX IF NOT EXISTS ix_index_entries_tenant_id ON index_entries (tenant_id);
CREATE INDEX IF NOT EXISTS ix_file_shares_tenant_id ON file_shares (tenant_id);
CREATE INDEX IF NOT EXISTS ix_shared_links_tenant_id ON shared_links (tenant_id);
CREATE INDEX IF NOT EXISTS ix_upload_sessions_tenant_id ON upload_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_guest_dropboxes_tenant_id ON guest_dropboxes (tenant_id);
CREATE INDEX IF NOT EXISTS ix_guest_dropbox_uploads_tenant_id ON guest_dropbox_uploads (tenant_id);

-- New writes must always carry a tenant and quota accounting must remain
-- monotonic and bounded.  NOT VALID preserves installations with unresolved
-- legacy rows while enforcing the invariant for every new or changed row.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_tenant_required') THEN
    ALTER TABLE users ADD CONSTRAINT users_tenant_required CHECK (tenant_id IS NOT NULL) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenant_quotas_usage_bounded') THEN
    ALTER TABLE tenant_quotas ADD CONSTRAINT tenant_quotas_usage_bounded
      CHECK (storage_quota_bytes >= 0 AND storage_used_bytes >= 0 AND storage_used_bytes <= storage_quota_bytes) NOT VALID;
  END IF;
END $$;

-- Empty/malformed context denies access. ``set_config(..., true)`` in the
-- request transaction prevents context leakage across pooled connections.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE files ENABLE ROW LEVEL SECURITY;
ALTER TABLE files FORCE ROW LEVEL SECURITY;
ALTER TABLE index_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE index_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE file_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_shares FORCE ROW LEVEL SECURITY;
ALTER TABLE shared_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE shared_links FORCE ROW LEVEL SECURITY;
ALTER TABLE upload_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE guest_dropboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE guest_dropboxes FORCE ROW LEVEL SECURITY;
ALTER TABLE guest_dropbox_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE guest_dropbox_uploads FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON tenants;
CREATE POLICY tenant_isolation ON tenants
  USING (id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON files;
CREATE POLICY tenant_isolation ON files
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid OR EXISTS (
    SELECT 1 FROM shared_links l WHERE l.file_id = files.id
      AND l.token = current_setting('app.public_link_token', true)
      AND (l.expires_at IS NULL OR l.expires_at > CURRENT_TIMESTAMP)
  ))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON index_entries;
CREATE POLICY tenant_isolation ON index_entries
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON file_shares;
CREATE POLICY tenant_isolation ON file_shares
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON shared_links;
CREATE POLICY tenant_isolation ON shared_links
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid OR (
    token = current_setting('app.public_link_token', true)
    AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
  ))
   WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON upload_sessions;
CREATE POLICY tenant_isolation ON upload_sessions
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON guest_dropboxes;
CREATE POLICY tenant_isolation ON guest_dropboxes
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid OR (
    encode(capability_hash, 'hex') = current_setting('app.dropbox_capability_hash', true)
    AND active AND expires_at > CURRENT_TIMESTAMP AND upload_count < max_uploads
  ))
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS tenant_isolation ON guest_dropbox_uploads;
CREATE POLICY tenant_isolation ON guest_dropbox_uploads
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid OR EXISTS (
    SELECT 1 FROM guest_dropboxes d WHERE d.id = guest_dropbox_uploads.dropbox_id
      AND encode(d.capability_hash, 'hex') = current_setting('app.dropbox_capability_hash', true)
      AND d.active AND d.expires_at > CURRENT_TIMESTAMP
  ));
