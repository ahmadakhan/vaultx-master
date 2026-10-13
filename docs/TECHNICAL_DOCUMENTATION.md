# VaultX Technical Documentation

**Document status:** Current implementation reference  
**Version:** 1.0  
**Audience:** Application engineers, security engineers, SREs, operators, reviewers, and integrators  
**Repository:** VaultX

> VaultX is a security-focused encrypted-storage prototype. This document describes the implementation as it exists in this repository. It is not a certification, authority to operate, or guarantee of zero-knowledge, post-quantum, HIPAA, GDPR, SOC 2, or FedRAMP compliance.

## 1. Purpose and scope

VaultX provides:

- authenticated user accounts and session rotation;
- client-side encryption for file content and selected metadata;
- encrypted keyword-index state and search-oriented token storage;
- file listing, download, trash, restore, purge, and sharing;
- optional TOTP and platform-authenticator WebAuthn ceremonies;
- tenant and quota foundations;
- resumable encrypted upload sessions;
- write-only guest dropboxes;
- audit-log creation, hash chaining, signing, and verification;
- browser transfer helpers and native mobile adapter boundaries.

The system is composed of a Next.js frontend, a FastAPI backend, SQLAlchemy models, PostgreSQL-compatible persistence, and filesystem-backed ciphertext storage. SQLite is used in synthetic tests only and does not provide PostgreSQL RLS behavior.

## 2. Repository layout

```text
.
├── backend/
│   ├── app/
│   │   ├── api/routers/       # HTTP route handlers
│   │   ├── core/              # auth, crypto policy, audit, tenant, WebAuthn
│   │   ├── middleware/        # headers and rate limiting
│   │   ├── models/            # SQLAlchemy persistence models
│   │   ├── schemas/           # Pydantic request/response contracts
│   │   ├── storage/           # ciphertext and staging filesystem
│   │   ├── config.py
│   │   ├── db.py
│   │   └── main.py
│   ├── migrations/            # standalone PostgreSQL migration artifacts
│   ├── tests/
│   ├── requirements.txt
│   └── pyproject.toml
├── frontend/
│   ├── app/                   # Next.js App Router pages
│   ├── components/            # application UI
│   ├── hooks/
│   ├── lib/                   # API, crypto, sharing, transfers
│   ├── native/                # native adapter source boundaries
│   ├── tests/
│   └── package.json
├── mobile/                    # standalone iOS/Android adapter sources
├── docs/
├── docker-compose.yml
└── security and design reports at repository root
```

## 3. System architecture

### 3.1 Runtime components

```text
Browser / native client
        │ HTTPS / bearer access token
        ▼
Next.js frontend ── /api rewrite ──► FastAPI backend
                                      │
                                      ├── Async SQLAlchemy ──► PostgreSQL
                                      ├── Filesystem/object staging
                                      ├── JWT/MFA/WebAuthn
                                      └── Audit and quota control
```

The frontend uses relative `/api/...` requests. Next.js rewrites these requests to the backend URL configured through `NEXT_PUBLIC_API_URL`. The FastAPI service itself does not add an `/api` prefix.

### 3.2 Request lifecycle

1. The client authenticates and receives an access token, refresh token, and encrypted key-bundle metadata.
2. The frontend unlocks client key material locally using the user password and bundle metadata.
3. Authenticated requests carry the access token in `Authorization: Bearer ...`.
4. The backend validates token type, expiry, revocation state, account status, and MFA claims.
5. The authenticated dependency establishes the transaction-local tenant context when a tenant is present.
6. Route-specific ownership, tenant, role, quota, and state checks run.
7. Database state and ciphertext storage are updated.
8. Mutating security-sensitive routes may append audit events.

### 3.3 Deployment topology

`docker-compose.yml` defines PostgreSQL, backend, and frontend services with named volumes for database data, signing keys, application keys, storage, and logs. Production deployment must add a real reverse proxy/TLS termination layer, secrets management, backups, monitoring, alerting, and a migration process. The repository intentionally rejects `APP_ENV=prod` until the prototype assurance gates are completed.

## 4. Configuration

### 4.1 Backend settings

The backend reads environment variables through `backend/app/config.py`; local dotenv loading is supported for development. Required categories include:

| Variable/category | Purpose |
|---|---|
| `APP_ENV` | `dev`, `staging`, or test-like operation; current code rejects `prod` |
| `APP_SECRET_KEY` | Application secret; minimum length enforced |
| `JWT_SECRET_KEY` | JWT signing secret; must differ from application secret |
| `JWT_ALGORITHM` | Restricted to HS256/HS384/HS512 |
| `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` | PostgreSQL connection settings |
| `DATABASE_URL` | Optional complete async database URL override |
| `MAIL_*` | Mail integration settings |
| `KEYS_DIR`, `FALLBACK_KEYS_DIR` | Server signing-key locations |
| `ALLOWED_ORIGINS` | CORS allowlist |
| `TRUSTED_PROXY_CIDRS` | Allowed proxy networks for forwarded client address handling |
| `MAX_UPLOAD_BYTES` | Maximum single upload bound |
| `STORAGE_DIR` | Ciphertext/staging root |
| `TRASH_RETENTION_DAYS` | Trash reaper retention interval |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` | WebAuthn relying-party policy |
| `WEBAUTHN_CHALLENGE_TTL_SECONDS` | Ceremony challenge lifetime |

Never commit `.env` files, passwords, signing keys, or private key material. Use an external secret manager for deployed environments.

### 4.2 Frontend settings

`frontend/sample.env` documents `NEXT_PUBLIC_API_URL`. The browser normally calls relative `/api` paths, and `frontend/next.config.ts` performs the rewrite. Do not put secrets in `NEXT_PUBLIC_*` variables.

## 5. Authentication and identity

### 5.1 Registration and login

Routes:

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`

Passwords are hashed server-side with the configured password-hashing implementation. Access and refresh tokens are typed JWTs. Refresh tokens are represented server-side by hashed JTI records, rotated on use, and revoked on logout, replay detection, account deactivation, MFA enablement, and MFA disablement.

For MFA-enabled accounts, password-only login returns a short-lived MFA challenge and does not return the vault key bundle. A full session is issued only after successful second-factor verification.

### 5.2 Client key bundle

The registration client generates user encryption material and submits encrypted bundle fields. The bundle includes:

- password salt and KDF metadata;
- encrypted master key;
- encrypted search key;
- encrypted private key;
- public key;
- bundle version.

The frontend unlocks the bundle locally and keeps active context in its session abstraction. Browser JavaScript memory is not a hardware-isolated secret store; XSS or malicious same-origin script remains in scope.

### 5.3 TOTP MFA

Routes:

- `POST /auth/mfa/setup`
- `POST /auth/mfa/enable`
- `GET /auth/mfa/status`
- `POST /auth/mfa/verify`
- `POST /auth/mfa/disable`

TOTP secrets are encrypted at rest. Verification uses a bounded time window, constant-time comparison, attempt budgets, and one-time markers for accepted time steps. Backup codes are single-use.

TOTP is not phishing-resistant. WebAuthn should be preferred for high-assurance authentication and step-up operations.

### 5.4 WebAuthn/passkeys

Routes:

- `POST /auth/webauthn/registration/options`
- `POST /auth/webauthn/registration/verify`
- `POST /auth/webauthn/authentication/options`
- `POST /auth/webauthn/authentication/verify`

The server uses the declared `webauthn` package adapter. Ceremonies persist:

- single-use 32-byte challenges;
- ceremony type;
- expiration;
- credential ID;
- credential public key;
- signature counter;
- user ownership.

The current policy requests platform authenticators and required user verification. The RP ID and origin must be configured explicitly and must not be derived from an untrusted request. If the dependency is absent, endpoints return `503`; they never accept a browser assertion without server verification.

Runtime startup calls `verify_webauthn_dependency()` before database initialization. The check validates package metadata and requires `webauthn>=2.8.0,<3`. Deployment images must install `backend/requirements.txt`; a source checkout alone is not a valid runtime image.

## 6. Cryptographic design

### 6.1 Current guarantees

The active browser format uses AES-GCM with:

- 256-bit keys;
- 12-byte IVs;
- 16-byte authentication tags;
- deterministic authenticated data binding format version, tenant/file identifier, chunk index, and plaintext length;
- per-file nonce plus counter-derived chunk IVs;
- framed ciphertext represented as `ciphertext || tag`.

The frontend crypto modules are:

- `frontend/lib/crypto/aes.ts`
- `frontend/lib/crypto/chunking.ts`
- `frontend/lib/crypto/bundle.ts`
- `frontend/lib/crypto/keys.ts`
- `frontend/lib/crypto/setupUserKeys.ts`
- `frontend/lib/crypto/zero-trust-crypto-streamer.ts`

### 6.2 Chunk format

The default plaintext chunk size is 5 MiB. A chunk IV is derived from the file nonce by writing a 32-bit big-endian chunk index into the final four bytes. The same file key and nonce must never be reused for a different file generation.

AAD conceptually follows:

```text
vaultx-chunk|v<format-version>|<tenant-or-file-id>|<chunk-index>|<plaintext-length>
```

Decryption rejects malformed IVs, invalid counters, unsupported versions, tag failures, chunk-size inconsistencies, and authenticated-size mismatches.

### 6.3 KDFs and compatibility

Current new derivation paths use PBKDF2-HMAC-SHA-256 with 600,000 iterations. Legacy bundles and link formats remain versioned for compatibility. Legacy compatibility must not be used as a basis for new links or new key bundles.

### 6.4 Post-quantum status

ML-KEM and hybrid post-quantum exchange are **not implemented**. The crypto streamer explicitly rejects post-quantum mode. Do not advertise PQ protection or use the placeholder as an asymmetric key exchange.

### 6.5 Memory handling

Owned typed-array buffers are overwritten in normal success/failure paths. Browser JavaScript cannot guarantee zeroization of immutable strings, garbage-collected copies, browser-managed `CryptoKey` internals, or hardware registers. Native secure-element integrations are required for stronger memory/key lifecycle guarantees.

## 7. File lifecycle

### 7.1 Upload paths

There are two related upload paths:

1. `POST /files/upload` accepts the established multipart encrypted-file flow.
2. Upload sessions use:
   - `POST /upload-sessions`
   - `GET /upload-sessions/{id}`
   - `PATCH /upload-sessions/{id}`
   - `POST /upload-sessions/{id}/finalize`
   - `DELETE /upload-sessions/{id}`

Upload sessions track owner, tenant, file ID, total bytes, current offset, chunk size, storage path, status, and expiry. Each PATCH requires `Upload-Offset` to equal the server offset. Requests are streamed to staging with bounded chunk limits. Finalization validates encrypted metadata fields, publishes the staged ciphertext, creates the `File` row, and is idempotent for an already-finalized session.

Finalization also validates optional encrypted search-token entries, reserves tenant storage atomically, and publishes the staged object only after database integrity checks. A retry returns the existing file instead of reserving quota a second time.

### 7.2 File states

Files move through these practical states:

```text
upload staging → complete session → finalized File
                         │
                         ├── active/live
                         ├── soft-deleted/trash
                         └── purged
```

Trash retains the ciphertext until explicit purge or the background retention reaper. Purge requires the owner and recent MFA where configured.

### 7.3 Download paths

Routes:

- `GET /files/{file_id}/download`
- `GET /shares/link/{token}/download`

Large ciphertext is streamed from filesystem storage and supports byte ranges. `frontend/lib/owner-download.ts` decrypts authenticated frames incrementally. When the File System Access API is available, plaintext is written to a sink without assembling the full file. Without it, the fallback is deliberately capped at 256 MiB.

### 7.4 Storage safety

Filesystem storage validates UUID-based paths, uses private directories, uses append offset checks, prevents overwrite publication, and truncates a partially appended payload after write failure. Staging cleanup and production object-store reconciliation must still be operationally verified.

## 8. Tenant isolation and quotas

Tenant helpers are in `backend/app/core/tenant.py`. Tenant ownership fields exist on files, index entries, shares, links, upload sessions, and dropboxes.

`backend/migrations/phase3_4_rls.sql`:

- creates transfer/dropbox tables where needed;
- adds tenant columns and indexes;
- backfills unambiguous ownership;
- enables and forces PostgreSQL RLS;
- installs deny-by-default policies based on `app.tenant_id`.

The authenticated dependency sets the transaction-local tenant context. Application predicates remain necessary; RLS is a database backstop, not a replacement for correct authorization.

Quota reservation uses a conditional update so concurrent reservations cannot exceed the configured quota. Finalization and purge must preserve the accounting invariant:

```text
0 <= storage_used_bytes <= storage_quota_bytes
```

Run the RLS migration as a migration owner. The runtime database role must not have `BYPASSRLS`.

## 9. Sharing and guest access

### 9.1 Account-to-account sharing

The owner obtains a recipient public key, wraps the file key with RSA-OAEP, and submits the wrapped key to `POST /shares`. The recipient unwraps it locally.

This is classical cryptography and is not post-quantum. The stored `permissions` field exists, but callers must verify the current authorization implementation before relying on write/admin permission semantics.

### 9.2 Guest download links

Routes:

- `POST /shares/link`
- `GET /shares/link/{token}`
- `GET /shares/link/{token}/download`
- `GET /shares/links/{file_id}`
- `DELETE /shares/link/{link_id}`

New links should carry high-entropy key material in the URL fragment. URL fragments are not sent in HTTP requests, but the browser page can read them locally. Access codes are sent in `X-Access-Code`, never query parameters. Links can expire and have download limits.

Legacy file-ID-derived key wrapping remains compatibility-only and must be migrated or disabled for high-assurance deployments.

### 9.3 Guest dropboxes

Routes:

- `POST /dropboxes`
- `POST /dropboxes/{capability}/uploads`

Capabilities are random bearer values; only SHA-256 hashes are stored. Dropboxes enforce expiry, maximum bytes, maximum uploads, and private staging. Guests cannot list, read, delete, or mutate submitted objects through the exposed routes.

Owners must still implement a secure review/acceptance workflow before treating a staged guest object as a normal file.

The owner review workflow is implemented through `GET /dropboxes/{dropbox_id}/uploads`, `GET /dropboxes/{dropbox_id}/uploads/{upload_id}`, `POST /dropboxes/{dropbox_id}/uploads/{upload_id}/accept`, and `POST /dropboxes/{dropbox_id}/uploads/{upload_id}/reject`. Uploads begin as `pending`. Acceptance validates the encrypted envelope, reserves tenant storage, publishes ciphertext, and creates a normal `File`. It is idempotent. Rejection removes staging and marks the object `rejected`; accepted objects cannot be rejected and rejected objects cannot be accepted. No malware scan is claimed.

## 10. Audit and observability

Audit routes:

- `GET /audit/logs`
- `GET /audit/verify`
- `GET /audit/security-summary`
- administrator equivalents under `/admin/audit/*`

Audit records contain an action payload, sequence, previous hash, current hash, timestamp, and signature. Verification checks continuity and cryptographic integrity. Logs must be reviewed for sensitive payload redaction before production use; tokens, passwords, private keys, access codes, and plaintext metadata must never be recorded.

Operational logs include request method, route template, status, and duration. Configure log retention and access separately from encrypted file storage.

## 11. API reference

### 11.1 Authentication

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/auth/register` | No | Register account and key-bundle metadata |
| POST | `/auth/login` | No | Password login or MFA challenge |
| POST | `/auth/mfa/setup` | Access | Begin TOTP enrollment |
| POST | `/auth/mfa/enable` | Access | Confirm TOTP enrollment |
| GET | `/auth/mfa/status` | Access | MFA status |
| POST | `/auth/mfa/verify` | MFA challenge | Complete login MFA |
| POST | `/auth/mfa/disable` | Access | Disable TOTP after verification |
| POST | `/auth/refresh` | No bearer required | Rotate refresh token |
| POST | `/auth/logout` | No bearer required | Revoke refresh token |
| GET | `/auth/public-key/{email}` | Access | Retrieve recipient public key |

### 11.2 WebAuthn

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/auth/webauthn/registration/options` | Access | Generate platform registration options |
| POST | `/auth/webauthn/registration/verify` | Access | Verify/store credential |
| POST | `/auth/webauthn/authentication/options` | Access | Generate authentication options |
| POST | `/auth/webauthn/authentication/verify` | Access | Verify assertion and issue MFA-assured session |

### 11.3 Files and transfers

| Method | Path | Purpose |
|---|---|---|
| POST | `/files/upload` | Multipart encrypted upload |
| GET | `/files` | List accessible files |
| GET | `/files/{id}` | File metadata/key material for authorized client |
| GET | `/files/{id}/download` | Encrypted range/stream download |
| DELETE | `/files/{id}` | Soft delete |
| POST | `/files/{id}/restore` | Restore from trash |
| DELETE | `/files/{id}/purge` | Permanent deletion |
| POST | `/upload-sessions` | Create resumable session |
| PATCH | `/upload-sessions/{id}` | Append bounded ciphertext at offset |
| POST | `/upload-sessions/{id}/finalize` | Publish staged upload as `File` |
| DELETE | `/upload-sessions/{id}` | Cancel session |

## 12. Database model summary

| Model/table | Responsibility |
|---|---|
| `users` | Identity, password hash, encrypted key bundle, MFA, tenant membership |
| `refresh_tokens` | Hashed JTI session rotation and revocation |
| `webauthn_challenges` | Expiring single-use ceremonies |
| `webauthn_credentials` | Credential public keys and sign counters |
| `files` | Encrypted metadata, IVs, file key wrapping, storage path, lifecycle |
| `file_shares` | Recipient wrapped file keys |
| `shared_links` | Guest bearer link policies and wrapped key material |
| `index_entries` | Encrypted search-token chains |
| `tenants` | Tenant identity and allocation policy |
| `tenant_quotas` | Atomic used/quota accounting |
| `admin_storage_allocations` | Quota-change history |
| `upload_sessions` | Resumable offset and staging state |
| `guest_dropboxes` | Expiring write-only capabilities and budgets |
| `guest_dropbox_uploads` | Private staged guest objects |
| `tamper_logs` / `audit_chain_anchors` | Signed, hash-chained audit evidence |

## 13. Mobile integration

### iOS

`mobile/ios/VaultXTransfer/VaultXBackgroundTransfer.swift` uses a background `URLSession` and device-only Keychain accessibility for wrapped keys. Integrators must provide an Xcode target, app-delegate background-session handoff, authenticated API client, offset reconciliation, and user-visible cancellation/retry policy.

The adapter is packaged as a Swift Package under `mobile/ios/Package.swift`:

```sh
cd mobile/ios
swift package resolve
swift build
```

### Android

`mobile/android/src/main/java/com/vaultx/transfer/VaultXBackgroundTransfer.kt` defines a WorkManager entry point and encrypted preferences. The worker currently fails rather than pretending to complete work; production integration must add the HTTP client, network constraints, offset query, authenticated frame retry, and notification/lifecycle handling.

The Android adapter module is buildable with:

```sh
cd mobile/android
gradle :vaultx-transfer:assemble
gradle :vaultx-transfer:compileDebugKotlin
```

These commands require a compatible JDK, Android SDK, Gradle installation, and dependency-network access.

### Security requirements for native integrations

- Store only wrapped keys and opaque transfer state.
- Bind transfer state to account, tenant, file-generation ID, and session ID.
- Query server offset after connectivity changes.
- Never retry from a stale offset.
- Do not log URLs containing fragments, access codes, keys, or plaintext metadata.
- Use device-only key accessibility and hardware-backed key wrapping where available.

## 14. Installation and development

### Backend

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp sample.env .env
# Fill all required development values; never use these as production secrets.
python3 -m compileall -q app
python3 -m pytest -q
```

### Frontend

```bash
cd frontend
npm install
npx tsc --noEmit
npm run lint
npm run test:crypto
npm run test:security
npm run dev
```

### Docker development

```bash
docker compose up --build
```

Before using Docker Compose, review every secret, volume, exposed port, health check, and backend/frontend URL. Compose defaults are development-oriented.

## 15. Migration and rollout procedure

1. Back up PostgreSQL and ciphertext storage.
2. Apply schema migrations using a migration owner:
   - `backend/migrations/phase3_4_rls.sql`
   - `backend/migrations/phase8_webauthn.sql`
3. Validate row counts and unresolved NULL tenant ownership.
4. Confirm the runtime role does not have `BYPASSRLS`.
5. Configure WebAuthn RP ID/origin for the exact deployment origin.
6. Install the declared WebAuthn dependency in the deployment image.
7. Run authentication, cross-tenant denial, quota race, upload finalization, and download-resume smoke tests.
8. Enable monitoring and backups.
9. Keep `APP_ENV` non-production until security review and deployment approval are complete.

## 16. Testing and verification

Current repository checks include:

```bash
# Backend
cd backend
python3 -m pytest -q
ruff check app test.py
python3 -m compileall -q app

# Frontend
cd frontend
npx tsc --noEmit
npm run test:crypto
npm run test:security
npm run lint
```

Important test boundaries:

- AES-GCM round trips, AAD binding, tag handling, IV/counter behavior, tampering, and truncation;
- upload offset monotonicity and bounded request size;
- dropbox capability hashing;
- WebAuthn policy/options when the dependency is installed;
- refresh-token rotation and replay revocation;
- MFA one-time-code and backup-code behavior;
- storage path traversal and no-overwrite publication;
- owner download sink behavior and bounded fallback.

Passing tests do not establish production compliance, PostgreSQL RLS correctness, browser memory zeroization, or mobile OS integration.

The PostgreSQL-only integration test is `backend/tests/test_rls_postgres.py`. It requires a PostgreSQL `DATABASE_URL`; it intentionally skips for SQLite or an unavailable test database. It applies the real RLS migration and verifies tenant A cannot read or insert tenant B rows. A skipped result is not evidence that RLS passed.

## 17. Threat model and security boundaries

### Protected against, subject to deployment correctness

- Unauthorized bearer-token use after revocation or refresh replay;
- cross-owner file access through ordinary route checks;
- malformed/base64/offset/chunk-size requests;
- ciphertext tampering detected by client-side AES-GCM;
- path traversal and destination overwrite in filesystem storage;
- brute-force pressure on TOTP and access-code paths through attempt controls;
- cross-tenant access when PostgreSQL RLS migration, tenant context, and role configuration are correctly deployed.

### Not solved by this repository

- malicious same-origin JavaScript/XSS reading browser-resident secrets;
- compromised browser, operating system, or device;
- guaranteed zeroization of JavaScript memory;
- post-quantum key exchange;
- traffic-analysis and access-pattern leakage;
- full malware/content scanning policy for guest uploads;
- complete native Android/iOS application integration;
- independent compliance certification or formal verification.

## 18. Operations and incident response

At minimum, operators should:

- rotate JWT/application secrets according to an approved schedule;
- protect signing-key directories with restrictive filesystem permissions;
- back up PostgreSQL and ciphertext storage together with tested restore procedures;
- monitor failed logins, MFA failures, refresh-token reuse, quota rejection, upload abandonment, RLS errors, and WebAuthn failures;
- revoke links and sessions during suspected compromise;
- disable accounts through the admin route and verify refresh-token revocation;
- preserve audit logs before investigating destructive events;
- document data-subject deletion and retention decisions separately from application purge behavior.

## 19. Compliance evidence status

`PHASE_7_COMPLIANCE_STATUS.md` is the authoritative short status record. The repository currently provides implementation evidence, not an attestation. Outstanding evidence includes:

- independent penetration testing;
- PostgreSQL RLS and quota concurrency testing;
- key-management review;
- retention and deletion verification;
- production infrastructure/IAM review;
- incident-response exercises;
- dependency/SBOM and vulnerability scanning;
- formal control mapping for SOC 2, HIPAA, GDPR, FedRAMP, or other frameworks.

## 20. Known limitations and change-control requirements

The following changes require security review rather than ordinary feature review:

- changing AES-GCM framing, AAD, nonce derivation, KDF parameters, or key-bundle versions;
- changing WebAuthn RP ID, origin, authenticator attachment, or user-verification policy;
- changing tenant predicates, RLS policies, quota arithmetic, or migration order;
- changing guest capability format, fragment key handling, access-code headers, or download accounting;
- adding persistence for plaintext metadata or browser key material;
- changing storage publication, cleanup, reaper, or backup behavior.

When making cryptographic-format changes, add a version, preserve explicit migration behavior, add known-answer tests, and document rollback compatibility before deployment.

## 21. Source references

- `README.md`
- `AUDIT_REPORT.md`
- `SECURITY_ASSURANCE_REVIEW.md`
- `SECURITY_REMEDIATION.md`
- `SECURITY_IMPLEMENTATION_SUMMARY.md`
- `ENTERPRISE_SECURITY_IMPLEMENTATION.md`
- `PHASE_7_COMPLIANCE_STATUS.md`
- `backend/app/main.py`
- `backend/app/config.py`
- `backend/app/api/routers/`
- `backend/app/core/`
- `backend/app/models/`
- `backend/migrations/`
- `frontend/lib/crypto/`
- `frontend/lib/owner-download.ts`
- `frontend/lib/resumable-upload.ts`
- `mobile/`
