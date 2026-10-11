# VaultX hardening and run status

Date: 2026-10-11. This supersedes the remediation status, not the historical evidence, in `AUDIT_REPORT.md`.

## Result

Security and UI hardening implemented; **not certified enterprise-ready**. The frontend production preview runs at `http://localhost:3000`. An isolated SQLite demo backend now runs on `127.0.0.1:8000`; PostgreSQL deployment remains unverified.

### Isolated demo verification

Started with user approval using `/tmp/omnirush/vaultx-demo.py`. Each launcher run creates a new private temporary directory, database and signing keys, with fresh in-memory secrets. Project dotenv loading is disabled; existing vault files are not used. Uploads are capped at 50 MiB for this demo; email is not configured. This disposable environment is not suitable for important data.

- Direct backend `/health`: `status=ok`, `database=ok`, `environment=test`.
- Frontend proxy `/api/health`: same healthy response.
- Frontend `/`: HTTP 200.
- Unauthenticated `/api/files`: HTTP 401.
- Both servers listen only on loopback. Browser registration/upload/download flows have not yet been manually verified.

## Implemented

- Signed MFA assurance, persistent authentication budgets, single-use challenges/codes, persisted session revocation and refresh replay handling.
- Public registration no longer grants administrator access; unsafe password-only admin provisioning and self-deactivation rejected.
- Credential redaction in audit/validation/model output; SQL parameter logging disabled.
- Owner-bound, sequential, size-bounded uploads and confined filesystem paths; immutable ciphertext publication; delete/restore safety and DB-first purge ordering.
- Salted slow access-code hashing, persistent link attempt limits, atomic download reservations, header-only access codes and constrained share permissions.
- Memory-only unlocked browser keys/tokens; new versioned 600k PBKDF2 key bundles with authenticated role binding; legacy bundle reads preserved.
- New public links carry a random wrapping secret in the URL fragment. Save complete links; they cannot be reconstructed after locking the owner's session. Revoke/recreate legacy links to obtain this protection.
- Crypto framing/tamper checks, structured API errors, matching local PDF worker, removal of vulnerable spreadsheet parser and unused placeholder dependencies.
- Updated frontend dependencies and one pnpm lockfile; production build no longer skips lint/type checks; security headers added.
- Restrained dashboard styling, responsive navigation/toolbars, keyboard file actions, better focus/contrast and accessible empty/error/loading states. No browser visual review performed.
- Python 3.13 containers, persistent signing-key/ciphertext volumes, no public database/backend ports or source bind mount, required database password, one worker until global rate limits are shared.

## Verified checks

| Check | Result |
|---|---|
| Backend isolated pytest suites | 17 storage cases plus an isolated subprocess running 21 identity cases; outer run: 18 passed |
| Frontend WebCrypto/API/session regressions | 8 passed |
| TypeScript `--noEmit --incremental false` | Passed |
| Frontend production build | Passed; 15 lint warnings remain |
| Frontend HTTP smoke check | HTTP 200; framing, MIME, referrer, permissions and partial CSP headers present |
| `git diff --check` | Passed at integration checkpoint |
| Backend `uv lock` | Regenerated with Python 3.13.16 |

Tests use synthetic configuration, temporary keys and SQLite, not existing vault data. Production PostgreSQL locking, full browser-to-backend workflows, container builds, backup restoration and accessibility/visual testing remain unverified.

## Release blockers and remaining risks

1. **Tracked sensitive artifacts:** Git tracks root `.env`, `backend/vaultx.db` and `backend/test_keys/server_signing_key.pem`. Contents were not opened. New ignore rules do not remove tracked files or history. Establish whether these contain live data, rotate exposed credentials using an approved plan, and remove sensitive artifacts from tracking/history. Preserve encryption and audit verification continuity; blindly replacing keys can destroy data access or historical verification.
2. **Backend dependency audit incomplete:** the first `pip-audit -r requirements.txt` attempt could not create its resolver environment because system ensurepip is missing. The existing requirements and uv lock still need advisory reconciliation and a clean production install test; regeneration alone does not prove vulnerability remediation.
3. Agent frontend audit reported an unpatched moderate `mammoth → argparse → sprintf-js` advisory and a high development-only `braces` advisory in ESLint tooling. Do not label the dependency tree vulnerability-free.
4. Deployment needs TLS termination, exact trusted proxy configuration, request body/concurrency limits, account quotas, abandoned staging cleanup and crash-orphan reconciliation. Global request throttling remains process-local.
5. Audit writes remain best-effort after mutations; externally anchored rollback detection and a formal migration/retention system remain architectural work. Reaper commits before blob removal, so interrupted cleanup can leave orphaned ciphertext rather than losing restorable files.
6. New installations need an explicit trusted administrator bootstrap procedure. Existing sessions may require login again. MFA configuration changes revoke sessions.
7. Memory-only session state deliberately locks on reload. This reduces persistence exposure but does not protect against JavaScript executing in an unlocked origin. CSP does not yet restrict scripts with per-request nonces.
8. Large-file download/decryption remains memory-buffered. Short metadata/file UI actions are tested at code level, not browser end-to-end. Remaining React hook warnings need review.

## Run

Frontend: `cd frontend`, install with the declared pnpm version, `pnpm build`, then `pnpm start --hostname 127.0.0.1`.

Full stack: review the blockers first, supply required secrets privately and a PostgreSQL service, then use the updated Compose configuration in an environment with Docker. Do not paste secrets into chat. Back up existing data and signing keys before any deployment or credential migration.
