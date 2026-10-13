-- WebAuthn ceremonies are single-use and are intentionally persisted in the
-- database so a challenge cannot be replayed across workers.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ceremony VARCHAR(16) NOT NULL,
    challenge BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS ix_webauthn_challenges_user_id ON webauthn_challenges(user_id);
CREATE INDEX IF NOT EXISTS ix_webauthn_challenges_expires_at ON webauthn_challenges(expires_at);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports BYTEA NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_webauthn_credentials_user_id ON webauthn_credentials(user_id);
