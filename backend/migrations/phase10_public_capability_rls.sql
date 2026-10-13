DROP POLICY IF EXISTS tenant_isolation ON files;
CREATE POLICY tenant_isolation ON files
  USING (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    OR EXISTS (
      SELECT 1 FROM shared_links l
      WHERE l.file_id = files.id
        AND l.token = current_setting('app.public_link_token', true)
        AND (l.expires_at IS NULL OR l.expires_at > CURRENT_TIMESTAMP)
    )
  )
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation ON shared_links;
CREATE POLICY tenant_isolation ON shared_links
  USING (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    OR (
      token = current_setting('app.public_link_token', true)
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
    )
  )
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation ON guest_dropboxes;
CREATE POLICY tenant_isolation ON guest_dropboxes
  USING (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    OR (
      encode(capability_hash, 'hex') = current_setting('app.dropbox_capability_hash', true)
      AND active AND expires_at > CURRENT_TIMESTAMP AND upload_count < max_uploads
    )
  )
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_isolation ON guest_dropbox_uploads;
CREATE POLICY tenant_isolation ON guest_dropbox_uploads
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (
    tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
    OR EXISTS (
      SELECT 1 FROM guest_dropboxes d
      WHERE d.id = guest_dropbox_uploads.dropbox_id
        AND encode(d.capability_hash, 'hex') = current_setting('app.dropbox_capability_hash', true)
        AND d.active AND d.expires_at > CURRENT_TIMESTAMP
    )
  );
