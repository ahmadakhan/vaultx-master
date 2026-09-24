# VaultX — Production-Readiness Audit (read-only)

**Date:** 2026-09-24
**Scope:** `backend/` (FastAPI) + `frontend/` (Next.js 15 App Router), build/deploy config, dependency manifests.
**Method:** direct source inspection of every router, core module, middleware, model/schema and the frontend crypto/API/component layer; `eslint` + `tsc --noEmit` on the frontend; PowerShell/git/Dockerfile/compose verification. **No files were modified.**

Commands run for evidence:

| Check | Result |
|---|---|
| `npm run lint` (frontend) | 20 warnings, 0 errors |
| `npx tsc --noEmit` (frontend) | exit 0 (no type errors) — but errors are ignored at build time (`next.config.ts`) |
| `git log` | `main` has **zero commits**; every path is untracked |
| `.python-version` / `pyproject` / `Dockerfile` | 3.13 / `>=3.13` / `python:3.11-slim` |
| `python -c "import PIL"` on this machine | PIL 12.3.0 present locally, **declared nowhere** |

**Path conventions.** Backend citations are relative to `backend/app/` unless a directory is given (`middleware/…`, `models/…`, `schemas/…`, `storage/…`); frontend citations are relative to `frontend/`. Resolved locations of the bare names used throughout:

| Cited as | Actual path |
|---|---|
| `deps.py` | `backend/app/core/deps.py` |
| `auth.py`, `files.py`, `shares.py`, `admin.py`, `audit.py`, `search.py`, `user.py` | `backend/app/api/routers/` |
| `net.py`, `security.py`, `server_keys.py`, `login_throttle.py`, `mfa.py`, `audit_*.py`, `exceptions.py` | `backend/app/core/` |
| `main.py`, `config.py`, `db.py` | `backend/app/` |
| `aes.ts`, `base.ts`, `context.ts`, `passphrase.ts`, `keys.ts`, `setupUserKeys.ts` | `frontend/lib/crypto/` |
| `file-manager.tsx`, `logs.tsx`, `trash.tsx`, `upload-modal.tsx`, `share-modal.tsx`, `login-form.tsx` | `frontend/components/` |
| `api.ts`, `types.ts` | `frontend/lib/` |
| `useAuth.ts` | `frontend/hooks/useAuth.ts` |
| `page.tsx` (login) / `dashboard/page.tsx` (shell) | `frontend/app/` and `frontend/app/dashboard/` — the app has only five route files, so registration is a mode of `login-form.tsx` rather than its own route |
| `shared/[token]/page.tsx` | `frontend/app/shared/[token]/page.tsx` |
| `admin/page.tsx` | `frontend/app/dashboard/admin/page.tsx` |

All `file:line` references in this report were re-validated programmatically against the working tree after the revision described in §8 — **219 line references across 30 distinct Python and 21 distinct TS/TSX files**: every target file exists and every cited range is within the file's length.

---

## 1. Severity summary

| # | Sev | Finding | Primary evidence |
|---|---|---|---|
| C1 | **Critical** | Every uploaded file is encrypted with an IV that is never persisted → all uploads are permanently undecryptable | `upload-modal.tsx:457,495,525-536`, `aes.ts:17-21`, `file-manager.tsx:474-479` |
| C2 | **Critical** | `setVaultXContext()` is never called → `getVaultXContext()` throws on every call → all authenticated UI is dead | `context.ts:15,19-24`; 12 call sites |
| C3 | **Critical** | MFA bypass server-side: the `mfa: pending` token is an ordinary `type="access"` JWT that no dependency rejects — only `DELETE /files/{id}` is MFA-gated | `auth.py:345-361`, `security.py:104,129`, `deps.py:54-68`, `files.py:722-728` |
| C4 | **Critical** | MFA login never restores the vault keys on the client → MFA accounts are unusable end-to-end | `login-form.tsx:135-163`, `auth.py:504` |
| H1 | High | Soft delete physically removes the blob while `/restore` only flips a flag → guaranteed data loss; "kept for 30 days" is false; no purge endpoint exists | `files.py:757-767`, `files.py:773-810`, `trash.tsx:143` |
| H2 | High | Refresh-token JWT is written verbatim into the signed audit log and exposed to admins | `auth.py:662`, `audit_decorator.py:87-91`, `admin.py:194-204` |
| H3 | High | Share links without an access code can never be decrypted (KDF input mismatch); links are silently created without any key material | `share-modal.tsx` createLink, `shared/[token]/page.tsx:89` |
| H4 | High | Access codes: unsalted single-round SHA-256, no throttling, and passed in the URL query string | `shares.py:283,470,543`, `shared/[token]/page.tsx:143` |
| H5 | High | Docker image is Python 3.11 while the source requires ≥3.12 → container cannot import the app | `net.py:15`, `Dockerfile:1`, `pyproject.toml` |
| H6 | High | `pyotp`, `qrcode`, `python-multipart`, Pillow are missing from `pyproject.toml`; Pillow missing from `requirements.txt` too | `pyproject.toml`, `requirements.txt`, `auth.py:478-499` |
| H7 | High | 4 gunicorn workers + process-local MFA cache/throttle/rate-limit → random 401s on delete, 4× effective limits, cache never pruned | `Dockerfile` CMD, `deps.py:28-30`, `login_throttle.py`, `rate_limit.py:81` |
| H8 | High | Proxy deployment never sets `TRUSTED_PROXY_CIDRS` → every audit entry records the reverse-proxy IP | `docker-compose.yml`, `net.py:43-61` |
| H9 | High | Signing keys live outside any volume → each redeploy generates a new key and invalidates every previously signed audit entry | `docker-compose.yml`, `Dockerfile:35`, `server_keys.py:195-232` |
| M1–M18 | Medium | See §4 | — |
| L1–L18 | Low/Quality | See §5 | — |

---

## 2. Critical findings

### C1 — The `file_iv` stored with every upload is not the IV used to encrypt the file

`aesEncryptArrayBuffer` generates its own random IV and returns it:

```ts
// frontend/lib/crypto/aes.ts:17-21
export async function aesEncryptArrayBuffer(plain: ArrayBuffer, key: CryptoKey) {
  const iv = new Uint8Array(genRandomBytes(IV_LEN).buffer as ArrayBuffer);
  const ct = await crypto.subtle.encrypt({ name: AES_ALGO, iv }, key, plain);
  return { ciphertext_b64: bufToB64(ct), iv_b64: bufToB64(iv.buffer) };
}
```

The uploader throws that IV away and sends an *unrelated* random `file_iv`:

```ts
// frontend/components/upload-modal.tsx:457
const fileEncIv = genRandomBytes(12);
const fileEncIv_b64 = bufToB64(fileEncIv.buffer as ArrayBuffer);
...
// 525-528 — encryptedChunk.iv_b64 is never read
const encryptedChunk = await aesEncryptArrayBuffer(chunkBuffer, chunkKey);
const chunkBytes = Uint8Array.from(atob(encryptedChunk.ciphertext_b64), (c) => c.charCodeAt(0));
...
// 536 — a different random value is what the server stores
formData.append("file_iv", fileEncIv);
```

The download path decrypts the whole blob with the stored IV — `const ivBytes = new Uint8Array(b64ToBuf(file_iv)); await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, ...)` (`file-manager.tsx:474-479`; same shape in `shared/[token]/page.tsx:195-205`) — so AES-GCM authentication fails for **every file uploaded through the UI**. Nothing anywhere records the real IV, so the loss is unrecoverable.

Note the exact value that reaches the server: inside the chunk loop the identifier `fileEncIv` resolves to the declaration at line 495, not the `Uint8Array` from line 457, and for a fresh upload the closure's `uploadFiles` still holds the pre-`setUploadFiles` array (React state updates do not mutate the captured value), so the `||` fallback fires and the request carries `bufToB64(genRandomBytes(12))` — a *valid* base64 IV of yet another random value. `_decode_b64` uses `validate=True` (`files.py:67`), so the upload **succeeds silently**; the mismatch only surfaces as an `OperationError` at decrypt time, outside the surrounding try/catch (see M3).

Second, independent defect on the same path: with `CHUNK_SIZE = 5 MB` (`upload-modal.tsx:37`), files >5 MB are encrypted **per chunk, each with its own random IV and its own 16-byte GCM tag**, then concatenated server-side (`storage/__init__.py:110-116`) and decrypted as a *single* GCM message on download. Even with the correct IV that can never validate; the on-disk format carries no per-chunk IV list.

**Fix direction:** generate the file IV once and pass it into the encrypt call (`aesEncryptArrayBuffer(plain, key, iv)`), storing exactly that value; for chunked uploads store a per-chunk IV (or derive one from a counter) alongside the chunk framing and decrypt segment by segment.

### C2 — The vault context is never initialised, so every authenticated feature fails

```ts
// frontend/lib/crypto/context.ts:13-24
let _ctx: VaultXContext | null = null
export function setVaultXContext(ctx: VaultXContext): void { _ctx = ctx }
export function getVaultXContext(): VaultXContext {
  if (!_ctx) throw new Error("Session expired — please log in again.")
  return _ctx
}
```

A whole-repo search shows `setVaultXContext` is referenced **only at its definition**; `login-form.tsx` instead writes the token/keys to `localStorage`/`sessionStorage` (`login-form.tsx:86-100`, `151`). Consequently `getVaultXContext()` throws at every call site:

* `file-manager.tsx:127` (list), `:186` (search), `:319` (download), `:522` (delete)
* `trash.tsx:71`, `:100` (list, restore)
* `logs.tsx:35`, `:58` (audit list, verify)
* `share-modal.tsx:89`, `:221`, `:273`

Effects: "Couldn't load files — Session expired" error state on the dashboard; silent no-ops on download (the throw happens outside the try/catch) and "Failed to delete/restore" alerts. The `if (!ctx.accessToken) { clearVaultXContext(); redirect }` guards are dead code — the call throws before the check. The admin page is the *only* screen that works, because it reads `localStorage` directly (`admin/page.tsx:95,105,120,140,163,178`).

**Fix direction:** call `setVaultXContext({accessToken, masterKey_b64, ...})` right after login/MFA verification (and on session rehydrate), delete the storage-based key copies, and make `getVaultXContext()` return `null` (or a typed Result) so the existing "session expired" branches actually run.

### C3 — MFA can be bypassed with the password alone

```python
# backend/app/api/routers/auth.py:345-361
mfa_token = create_access_token(
    {"sub": str(user.id), "mfa": "pending"},
    expires_delta=timedelta(minutes=10),
    jti=uuid.uuid4().hex,
)
return {
    "access_token": mfa_token,          # ordinary type="access" JWT
    "refresh_token": "",
    "token_type": "bearer",
    "mfa_required": True,
    "keys": _keys_response(user),        # encrypted key bundle, pre-MFA
}
```

No dependency rejects `mfa == "pending"` — `create_access_token` stamps `type="access"` (`security.py:104,129`) and `get_current_user` decodes with `expected_type=ACCESS_TOKEN_TYPE` (`deps.py:55`) — so for its 10-minute lifetime that token grants full API access: file list/metadata, download, upload, restore, share and link creation, `/search`, `/user/*` and, for admins, all of `/admin/*`, with **no TOTP step**. The single exception is `DELETE /files/{id}`, which is wired to `get_current_user_mfa_verified` (`files.py:728`) and does reject a pending token — that dependency exists but is applied nowhere else (see M16), which is why the bypass is not "file deletion is protected" but rather "everything else is unprotected". The response also hands over the encrypted master/search/private key bundle before the second factor is presented, which defeats MFA for an attacker who already knows the password (they derive the password key client-side and decrypt the bundle).

**Fix direction:** issue a distinct token type (e.g. `type="mfa"`) and have `get_current_user` accept only `type="access"` tokens without an `mfa` claim; return `keys` only from `/auth/mfa/verify`.

### C4 — MFA login leaves the client without any keys

`/auth/mfa/verify` returns `TokenResponse` only (`auth.py:504`), and the client stores nothing but the token:

```ts
// frontend/components/login-form.tsx:147-153
const res = await api.post("/auth/mfa/verify", { code: mfaCode }, mfaToken || undefined)
const accessToken = data.access_token
localStorage.setItem("vaultx_access_token", accessToken)
router.push("/dashboard")
```

`sessionStorage.vaultx_master_key` / `vaultx_search_key` / `vaultx_private_key` / `vaultx_keyword_chain` are never populated (they are written only in the non-MFA branch, `login-form.tsx:87-100`), and `setVaultXContext` is never called either (C2). The result: after an MFA login *every* crypto operation fails — download throws `Missing master key — please log in again.` (`file-manager.tsx:429`) and upload throws `Missing search key` (`upload-modal.tsx:427`). The `/auth/login` MFA-pending response is the only place `keys` is available and the client discards it. MFA accounts are unusable end-to-end; this is almost certainly why the backend "helpfully" leaks the bundle pre-MFA (C3).

**Fix direction:** return the key bundle (or expose a one-time key-fetch endpoint) after successful MFA verification and populate both the sessionStorage values and the in-memory context in `handleMfaSubmit`.

---

## 3. High findings

### H1 — Soft delete destroys the blob, and restore cannot bring it back

```python
# backend/app/api/routers/files.py:757-767  (DELETE /files/{id})
# Physically delete the blob from filesystem storage
if file.storage_path:
    storage = get_storage()
    storage.delete_blob(str(file.id))
file.deleted = True
await db.commit()
```

`storage.delete_blob` unlinks the ciphertext and removes the blob directory (`storage/__init__.py:184-192`). `POST /files/{id}/restore` (`files.py:773-810`) only sets `deleted = False`, leaving `storage_path` pointing at a file that no longer exists. After a restore, a range download fails with **404 "File blob not found on disk"** (`files.py:630-631`) and a non-range download returns an empty `ciphertext` (`f.ciphertext` is `None` for all new uploads). There is no purge/reaper endpoint anywhere (a repo-wide search for `purge` returns only a docstring and an unrelated script), and `trash.tsx:143` tells the user files are *"kept for 30 days before permanent removal"*, which is false. Deletion is therefore irreversible orphan-row creation + data loss.

**Fix direction:** make delete a metadata-only operation, add an explicit `DELETE /files/{id}/purge` plus a scheduled reaper that removes blobs and rows after the retention window, and only then delete from storage.

### H2 — The refresh token is written verbatim into the immutable audit log

```python
# backend/app/api/routers/auth.py:662
@audit_event("token_refresh", resource_fields=("refresh_token",))
async def refresh_token(request: Request, refresh_token: str = Body(..., embed=True), ...)
```

`audit_decorator.py:87-91` copies every named parameter into the signed payload, so the **raw refresh JWT** becomes `entry_json.resource.refresh_token` in `tamper_logs`. `/admin/audit/logs` returns that JSON to any admin (`admin.py:194-204`), and the whole point of the audit table is that rows are never rewritten — so a live credential is permanently stored and permanently exposed. This also makes the audit-verify failure message (`verify_audit_chain`) print token material into logs/API errors.

**Fix direction:** never include credentials in `resource_fields`; log only a hash prefix of the `jti` (e.g. `refresh_jti_hash[:12]`).

### H3 — Share links without an access code can never be decrypted

Creation (`frontend/components/share-modal.tsx`, `createLink`) derives the key-wrapper passphrase as:

```ts
const tokenPass = `vaultx_link_${file.id}_${fileKeyB64.substring(0, 16)}`
```

while the guest page derives:

```ts
// frontend/app/shared/[token]/page.tsx:89
const tokenPass = `vaultx_link_${meta.id}_`
```

Different PBKDF2 inputs → different AES-GCM keys → `crypto.subtle.decrypt` always throws, and the guest sees *"Failed to decrypt file metadata. Check your access code."* The guest cannot know the missing suffix (it is derived from the file key, which only the owner has), so this branch is broken by construction. Additionally, when `sessionStorage.vaultx_kf_<id>` is absent, `createLink` proceeds with `fileKeyB64 === null` and posts `encrypted_kf_b64: null` — the API happily stores a link with no key material (`shares.py:296-303`) and the UI reports *"Shareable link created!"*. Guests then get `Could not decrypt file key.`

**Fix direction:** share one derivation helper between both entry points, pass the derived wrapper key (not the raw KF) through a single code path, refuse to create a link when the key material is unavailable, and surface that as a UI error.

### H4 — Access codes are weakly hashed, unthrottled, and leak into URLs

```python
# backend/app/api/routers/shares.py:283-285 (create) / 470-474 (metadata) / 543-547 (download)
access_code_hash = hashlib.sha256(payload.access_code.encode()).hexdigest()
...
if not secrets.compare_digest(access_hash, link.access_code_hash):
    raise AuthorizationError("Invalid access code")
```

* Unsalted single-round SHA-256 over a short user-chosen secret → a database disclosure yields the code instantly (rainbow/gpu brute force of a 4–8 character code).
* No per-link throttling exists on either `/shares/link/{token}` or `/shares/link/{token}/download`; the only limit is the global token bucket (`rate_limit.py`), i.e. ~100 guesses/s per source → a 6-digit code falls in minutes.
* Worse, the *offline* attack is free: `/shares/link/{token}` releases `encrypted_kf_b64`, `encrypted_kf_iv` and `kf_salt` to anyone holding the token, so the access code can be brute-forced locally against PBKDF2 (`passphrase.ts:5`, 100k iterations) without touching the server.
* The code is transmitted as a URL query parameter (`shared/[token]/page.tsx:143`: `/shares/link/${token}/download?access_code=...`), which lands in uvicorn/gunicorn access logs, the Next.js proxy logs, browser history and any `Referer` header.

**Fix direction:** hash with a per-link salt and a slow KDF (scrypt/PBKDF2), add a per-link attempt counter/lockout, require the code in a request body or header, and rate-limit the two guest endpoints separately.

### H5 — The container runs a Python that cannot parse the source

* `backend/.python-version` → `3.13`; `pyproject.toml` → `requires-python = ">=3.13"`.
* `backend/app/core/net.py:15` uses PEP 695 syntax: `type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network` (Python **3.12+**).
* `backend/Dockerfile:1` → `FROM python:3.11-slim` (both builder and runtime).

`gunicorn app.main:app` therefore dies at import with `SyntaxError: invalid syntax` on Python 3.11 — the documented `docker compose up` deployment cannot start at all. It works locally only because this machine has Python 3.14.6.

**Fix direction:** bump both Docker stages to `python:3.13-slim` (or rewrite the alias with `TypeAlias`).

### H6 — Runtime dependencies are undeclared; a clean install is broken

`pyproject.toml` (the declared source of truth) lists neither `pyotp`, `qrcode`, nor `python-multipart`, yet:

* `auth.py:478-479, 592` import `pyotp` / `qrcode` → every `/auth/mfa/*` endpoint raises `ImportError`.
* `files.py` declares `Form(...)`/`UploadFile` parameters → FastAPI raises *"python-multipart is required"* for `/files/upload`.
* `qrcode.QRCode(...).make_image()` (`auth.py:496-499`) needs **Pillow** — absent from both `pyproject.toml` *and* `requirements.txt`. (Pillow 12.3.0 is installed locally, which masks the failure.)
* `requirements.txt` is otherwise inconsistent: `passlib==1.7.4` is listed **twice** (lines 8 and 31), `bcrypt==4.0.1` is pinned there while `pyproject.toml` asks for `bcrypt<4.1`, and the Docker build installs from `requirements.txt` while developers use `uv.lock`/`pyproject` → three divergent dependency definitions.

**Fix direction:** add `pyotp`, `qrcode[pil]`, `python-multipart` to `[project].dependencies`, delete the duplicate line, and make the Dockerfile install from `pyproject.toml`/`uv.lock`.

### H7 — Stateful security logic + a 4-worker production command

```dockerfile
# backend/Dockerfile (final line)
CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", ...]
```

Everything security-relevant is stored in process memory:

* `_mfa_verified_cache` (`deps.py:28-30`) is a module-level dict. With 4 workers, `POST /files/{id}` (the only endpoint using `get_current_user_mfa_verified`, `files.py:728`) succeeds only if the request lands on the worker that handled `/auth/mfa/verify` → MFA users get **401 "MFA verification required for this action" on ~75 % of delete attempts**.
* The cache is never pruned (entries accumulate for the life of the worker) and is keyed by `jti`, which does not exist at all on tokens minted by `/auth/refresh` (`auth.py:764` calls `create_access_token({"sub": ...})` with no `jti`) → after any refresh, `get_current_user_mfa_verified` can *never* pass; an MFA user must fully re-login.
* `login_throttle` (`core/login_throttle.py`) and the token buckets (`rate_limit.py:81`) are per-process → the effective login budget is 5×4 = 20 attempts and the effective global rate limit is 400 req/s.
* `get_current_user_mfa_verified` is also **fail-open**: any exception while decoding returns the user unchanged (`deps.py:116-120`).

**Fix direction:** move the MFA-verified marker, throttle counters and rate-limit buckets to Redis (or make MFA state part of the token/DB), run a single worker until then, add the `jti` to refreshed tokens, and replace the fail-open `except: return current_user` with a deny.

### H8 — Behind the shipped proxy, every audit IP is the proxy's IP

`docker-compose.yml` puts the Next.js container in front of the backend but never sets `TRUSTED_PROXY_CIDRS`, so the default `127.0.0.1/32` applies (`config.py:62`). `client_ip_from_scope` (`core/net.py:43-61`) ignores `X-Forwarded-For` unless the socket peer is trusted, so every request is attributed to the Docker bridge address of the frontend container. Consequences: all audit entries record the proxy IP (forensics for `login`, `file_download`, `file_delete`, `link_created` become useless), and the global rate limiter treats the whole user base as one client (a single user can exhaust the shared bucket).

**Fix direction:** set `TRUSTED_PROXY_CIDRS` to the compose network (e.g. `172.16.0.0/12`) and keep the audit log's resolved-IP field documented; consider bucketing by `sub` for authenticated routes.

### H9 — A redeploy silently invalidates the whole audit trail

`server_keys.py:195-232` generates the RSA signing key under `KEYS_DIR` (`/etc/vaultx/keys`, `Dockerfile:35`) when absent and refuses to regenerate if a pair already exists — deliberately, because rotation would break every historical signature. But `docker-compose.yml` mounts no volume for `/etc/vaultx`, so every `docker compose up --build` starts with an empty directory and mints a **new** key pair. Thereafter `verify_audit_chain` reports `Signature verification failed at entry N` (and `Anchor signature verification failed`) for all pre-existing rows — the flagship tamper-evidence feature self-destructs, and the tool that is supposed to detect tampering reports tampering.

**Fix direction:** mount a named volume for `/etc/vaultx/keys` (or inject the PEMs as a secret), and gate startup on key fingerprint continuity.

---

## 4. Medium findings

**M1 — The client never uses refresh tokens and never calls `/auth/logout`.** Grepping the whole frontend for `auth/refresh`, `auth/logout` or `vaultx_refresh_token` yields only UI labels. `/auth/login` returns a refresh token that is stored nowhere; the logout button (`dashboard-layout.tsx:204`) just clears local state and redirects. Consequences: sessions die hard after 60 minutes (`JWT_EXPIRE_MINUTES`) even though rotation/revocation machinery exists, and the server keeps an active, unrevoked `RefreshToken` row for 30 days for every login — including logouts. `/auth/refresh`'s reuse *detection* (auth.py:712-728, a nice implementation) is therefore unreachable in practice.

**M2 — Sensitive key material is still persisted in `sessionStorage`, contradicting the stated design.** `context.ts:9-12` documents "keys are intentionally NOT persisted … any XSS can read those stores", yet `login-form.tsx:87-89` writes the master key, the search key and the **RSA private key** to `sessionStorage`, and `file-manager.tsx:93` / `shared/[token]/page.tsx:102` write plaintext per-file keys (`vaultx_kf_<id>`) there too. The refactor to in-memory storage was only half-applied (this is also why C2 exists).

**M3 — Silent failures around the download crypto path.** In `file-manager.tsx` the `try` block ends at line 415 and its `catch` at 416-426, so everything after it — the `sessionStorage` lookups (428), the `throw new Error("Missing master key…")` (429), the RSA unwrap (440-459) and the final `crypto.subtle.decrypt` (474-479) — runs **outside** any error handler. Any failure there becomes an unhandled promise rejection: the spinner is left at "downloading" and the user gets no message (the aborted case at 464 is the only escape). Given C1, that is the default path for every file today.

**M4 — Validation errors are unreadable to the user.** `main.py:59-78` registers handlers only for `VaultXError` and bare `Exception`; `RequestValidationError` keeps FastAPI's default body where `detail` is a *list* of objects. The client does `throw new Error(data_.detail)` (`api.ts:32,62,135`), which stringifies to `"[object Object]"`. Every schema-level rejection (bad email, short password, malformed UUID, missing form field) shows that string.

**M5 — The user-facing audit view reads a field the API does not return.** `logs.tsx:38-44` maps `log.entry`, but `GET /audit/logs` returns `TamperLogRead.entry_json` (`schemas/audit.py:16-25`, `audit.py:57-69`). `RawLog` (`lib/types.ts:26-32`) also declares `entry` and `prev_hash`, neither of which exists. Rows therefore render with an empty entry object (no action/timestamp/IP). Note `admin/page.tsx:456` reads `entry_json` correctly, so the two screens disagree.

**M6 — The CORS expose-list is inverted.** `main.py:156` exposes `X-Total-Count`, which no endpoint sets. Meanwhile every custom header the client actually consumes — `X-File-Iv`, `X-Metadata-Ciphertext`, `X-Metadata-Iv`, `X-Encrypted-Kf`, `X-Encrypted-Kf-Iv`, `X-Wrapped-Key`, `X-Kf-Salt`, `X-Created-At`, `Content-Range`, `Accept-Ranges` (`files.py:658-706`, `shares.py:581-592`, consumed in `file-manager.tsx:361-368` and `shared/[token]/page.tsx:148-154`) — is unexposed. Same-origin use via the Next rewrite hides this today, but any deployment that calls the API on a separate origin breaks range parsing (progress/resume silently report 0 %) and header-carried metadata.

**M7 — MFA codes are not throttled.** `mfa_verify` (auth.py:504-585) and the login-time code check (auth.py:324-350, which also runs *after* `login_throttle.reset(key)`) call only `_record_login_failure` for auditing and never `login_throttle.record_failure`. With `valid_window=1` (±30 s) a 6-digit code can be brute-forced at the global rate limit (≈100 attempts/s → 10⁶ combinations in ~3 h, and any window overlap multiplies valid codes). Backup codes are single-use but equally unthrottled.

**M8 — Guest link downloads are unaudited and miscount.** `download_shared_link_file` (`shares.py:497-592`) has no `@audit_event`, so the only guest-access surface in the product leaves no trace (owner downloads are audited). It also accepts a `range` parameter and **ignores it**, while advertising `Accept-Ranges: bytes`; it increments `download_count` on every request, including aborted/resumed/turbo-loaded ones, so a `max_downloads: 1` link can be exhausted without a complete download. The increment is also a non-atomic read-modify-write (`link.download_count + 1`), so parallel requests can exceed the cap.

**M9 — Staging area grows without bound.** `write_chunk` creates `storage/staging/<upload_id>/…` (`storage/__init__.py:70-91`) and nothing cleans it up unless `cancel_upload` is called — which happens only on the size-limit error path (`files.py:213-217`). The client has no cancel call at all (pausing/stopping/aborting just stops sending). Any authenticated user can therefore persist arbitrary amounts of data (up to `MAX_UPLOAD_BYTES` = 11 GB per upload id, and upload ids are client-chosen UUIDs), and `chunk_index` is never validated against `total_chunks` (e.g. index 10⁹ with `total_chunks=1` is accepted and written). The whole request body is also buffered in RAM (`chunk_bytes` + `b"".join`, `files.py:206-222`) before being appended, so a single-chunk 11 GB upload is a memory-exhaustion vector.

**M10 — Admin activity is invisible to the audit trail, and admin user creation produces a broken account.** `admin.py` never imports `audit_event`, so create-user, deactivate-user, list-users, list-audit-logs and verify-chain are only `logger.info` lines — privileged actions are absent from the very trail the product advertises. Also: (a) an admin can deactivate **themselves** (`delete_user` has no self/last-admin guard, admin.py:136-159) leaving nobody able to administer the instance; (b) there is no reactivate endpoint at all; (c) `create_user` provisions `password_salt_b64=b""`, `enc_*_b64=b""`, `public_key_b64=b""` (admin.py:102-115) with a comment claiming the password "must be changed by the user on first login" — no such flag or flow exists. `/auth/login` succeeds and hands back those empty strings, but the client then runs `deriveMasterKey(password, "")` — an empty salt is falsy, so `keys.ts:11-12` mints a *fresh random salt* — and `decryptToB64("", "")` drives `crypto.subtle.decrypt` with a **zero-length IV**, which throws (`aes.ts:23-27`, `base.ts:8-13`). The account is therefore unusable rather than merely key-less: the user never gets past the login form, and no token is stored because the bundle unwrap (`login-form.tsx:70-84`) runs before `localStorage.setItem` (`login-form.tsx:86`). There is also no re-key endpoint, and sharing *to* the account fails with "User not found" because the empty public key is falsy, `auth.py:831-833`; (d) the bcrypt 72-byte `ValueError` is surfaced as a 403 `AuthorizationError` instead of a 422 (admin.py:97-100).

**M11 — N+1 queries in `GET /admin/users`.** `list_users` issues one `UserRole` query per user (admin.py:55-73), i.e. up to 201 round-trips for `limit=200`. The files list was explicitly de-N+1'd (`files.py:320-345`), so this is an oversight rather than a pattern.

**M12 — There are no automated tests, and the build cannot fail on quality checks.** `pyproject.toml` sets `testpaths = ["tests"]` but `backend/tests/` does not exist; `backend/test.py` is a 306-line manual script that drives a live server with `requests` and contains no `def test_*`, so `pytest` exits 5 ("no tests ran"). There is no `.github/` directory or any CI config. On the frontend, `next.config.ts` sets `eslint.ignoreDuringBuilds: true` **and** `typescript.ignoreBuildErrors: true`, so the 20 current warnings — including unused imports such as `clearVaultXContext` in `upload-modal.tsx:33` and `QrCode`/`Switch` in `share-modal.tsx` — can never block a release. (`npx tsc --noEmit` currently passes, so the switch is pure risk.)

**M13 — Frontend dependency hygiene.**
* `"crpyto-js": "0.0.1-security"` — a misspelling of `crypto-js` that resolves to npm's placeholder "security holding package"; nothing imports it (nor the real library), yet `@types/crypto-js` is a devDependency.
* `"eslint-plugin-next": "^0.0.0"` — a 2015 placeholder package.
* Both `package-lock.json` and `pnpm-lock.yaml` are committed while `packageManager` pins `pnpm@10.15.1` → guaranteed drift between the two lockfiles.
* `xlsx@0.18.5` — the npm-hosted SheetJS build is abandoned and carries known CVEs; the vendor ships fixes only through their CDN tarball.
* `pdfjs-dist` is declared `^5.4.394` but `upload-modal.tsx:104-106` loads the worker from `https://cdn.jsdelivr.net/npm/pdfjs-dist@4.6.82/...` — a hard-coded **v4** worker for a **v5** library (pdf.js requires matching versions), fetched from a third-party CDN at runtime with no integrity check and no local CSP on the Next app.

**M14 — Development logging leaks data.** `db.py:21` sets `echo=(settings.app_env == "dev")`, which prints every statement **with bound parameters** — password hashes, encrypted key bundles, ciphertext, emails — to the application log.

**M15 — Dead/incorrect runtime config on the frontend.** `config/index.ts` reads `next/config`'s `serverRuntimeConfig.apiUrl`, but `next.config.ts` defines only `publicRuntimeConfig` (a Pages-Router-only feature that the App Router ignores) and no `serverRuntimeConfig`; the module is imported by nothing, so `apiUrl` would be `undefined` if it were. `next.config.ts` also proxies `/api/:path*` to `NEXT_PUBLIC_API_URL`, so the client-side `NEXT_PUBLIC_API_URL` value in `docker-compose.yml` (`http://backend:8000`) is baked into browser bundles where that hostname does not resolve — harmless today only because `lib/api.ts` uses relative paths.

**M16 — MFA enforcement exists but is wired to exactly one endpoint, and to process-local state.** `get_current_user_mfa_verified` (`deps.py:94-127`) implements the intended policy — its docstring names "file deletion, user deactivation, or audit log access" — yet a repo-wide grep finds only two references: the import (`files.py:37`) and the dependency on `DELETE /files/{id}` (`files.py:728`). `POST /files/batch` reads like a bulk mutation but is read-only (`files.py:385-390`, `list_files_by_ids`), so nothing else is MFA-gated: user creation/deactivation and both audit endpoints in `admin.py`, every share/link endpoint, `/search` and all of `/user/*` accept a token minted *before* the second factor was presented. Even where the dependency does apply, the state it consults is `_mfa_verified_cache`, an in-process dict keyed by the access token's `jti` (`deps.py:30`) filled only by `mfa_verify` with a 1800 s window (`auth.py:578-587`): with the 4 gunicorn workers from the Dockerfile only the worker that served the verification accepts the delete, so identical requests randomly succeed or fail (H7), entries are never pruned, a restart forgets them, and `except Exception: return current_user` (`deps.py:119-120`) fails **open** whenever the token cannot be decoded (L9). Fix direction: carry the second-factor state as a token claim (e.g. `amr: ["pwd","otp"]`) or move it to Redis, and apply the dependency by *policy* (all mutating and all `/admin/*` routes) instead of by one-off choice.

**M17 — `permissions` on a share is a control that controls nothing.** `FileShareCreate.permissions` is validated to `read|write|admin` (`schemas/share.py:30`), persisted (`shares.py:135`), silently overwritten on re-share (`shares.py:121`) and echoed back to the client (`shares.py:65`) — and a whole-backend grep finds no other reference: no authorization decision anywhere reads the column, so `read`, `write` and `admin` shares are byte-for-byte equivalent. Because the share API is download-only today, this escalates nothing *yet*; the risk is a false control that will silently grant `write` semantics the moment a mutating recipient endpoint is added, plus the misleading permission picker in `share-modal.tsx`. Related gaps in the same create schema: `access_code` allows 4 characters (`schemas/share.py:72`) although the link's key wrap is unsalted single-round SHA-256 (H4) — 10⁴ offline guesses; `expires_at` (`schemas/share.py:73`) has no "must be in the future" validator and is stored unchecked (`shares.py:318`), so a link can be created already-dead and the UI reports success; and the expiry/max-download checks are copy-pasted verbatim at `shares.py:457-474` and `shares.py:531-548`, where a future fix to one will silently miss the other. Fix direction: one `require_share_permission(share, "write")` helper (or delete the field), `min_length=6`+digits for access codes, and a `field_validator` rejecting past dates.

**M18 — The client pins the *legacy* KDF parameters and ignores the versioned bundle the backend already implements.** `security.py:35-41` defines `LEGACY_KDF_ITERATIONS = 150_000` / `CURRENT_KDF_ITERATIONS = 600_000` and `LEGACY_KEY_BUNDLE_VERSION = 1` / `CURRENT_KEY_BUNDLE_VERSION = 2`, with a comment stating they "must stay in sync with `frontend/lib/crypto/keys.ts`". They are not: `keys.ts:3` hard-codes `PBKDF2_ITERATIONS = 150_000` (the *legacy* value), `deriveMasterKey()` (`keys.ts:6-23`) takes no iteration parameter at all, `prepareUserKeyBundle()` (`setupUserKeys.ts:28-37`) never sends `kdf_iterations`/`key_bundle_version`, and the login handler calls `deriveMasterKey(password, keys.password_salt_b64)` (`login-form.tsx:68`) without forwarding the `kdf_iterations` that `_keys_response()` just returned (`auth.py:103-104`). Consequences: (1) every account in existence is a legacy 150k bundle, i.e. a quarter of the offline-guessing cost the backend's own constant declares, and the AES-GCM-without-AAD construction is still what protects the bundle although v2 was defined to fix it (`schemas/auth.py:54-56`, `aes.ts:17-21` has no `additionalData`); (2) `RegisterPayload` *rejects* any `kdf_iterations` below 600 000 (`schemas/auth.py:97-106`), so the shipped client could not honestly declare its parameters even if it tried — the v2 path is unreachable from the UI; (3) because the parameter set is only knowable from the constant, any future client that respects `kdf_iterations` will create bundles that *this* client silently derives with the wrong work factor (`login-form.tsx:68-84` would then fail with an AES-GCM auth error, indistinguishable from a wrong password). Fix direction: have `keys.ts` accept `{iterations, version}` (defaulting to legacy only when the server reports a legacy bundle), send both fields on registration, add AAD/hkdf-based v2 semantics in one release, and keep `LEGACY_*` purely for reading old rows.

---

## 5. Low / code-quality findings

| # | Finding | Evidence |
|---|---|---|
| L1 | `files.py:242` calls the **private** `storage._final_path()`; `files.py:633` uses `assert` for a None-check (removed under `python -O`) | `files.py:242,633` |
| L2 | Range parsing rejects valid suffix ranges (`bytes=-500` → `int("")` → 400) while accepting `bytes=abc-`-style garbage paths | `files.py:616-631` |
| L3 | `upload_file` hand-rolls `json.loads(tokens_json)` and indexes `t["token"]` (KeyError → 500) although the validating helper `parse_token_entries` exists and is exported but **never used** | `files.py:249-284`, `schemas/file.py:50` |
| L4 | Every download sends `Range: bytes=0-` (`file-manager.tsx:353`), so a legacy DB-inline file (`storage_path` NULL, `ciphertext` in the row) hits `files.py:630-631` and returns **404 "File blob not found on disk"**; the client only recovers by falling into its `catch` and re-fetching the un-ranged JSON endpoint (`file-manager.tsx:416-425`). Functionally it works, but every such download costs a wasted failing request and is fully buffered in memory instead of streamed/resumable | `files.py:611-631` vs `file-manager.tsx:346-358,416-425` |
| L5 | `link_url` is built from an unvalidated `Host` header (host-header injection into a returned URL) | `shares.py:339-353` |
| L6 | `base64.b64decode` without `validate=True` for link key material; helper duplication (`_decode_b64` in both `files.py` and `shares.py`) diverges on status code (422 vs raw 400 `HTTPException`) | `shares.py:296-303,44-52` |
| L7 | `share_file` looks the recipient up with exact equality (`User.email == payload.recipient_email`) instead of the project's own `email_matches()` helper, whose docstring states that lookups "must not rely on exact equality" because rows created before normalisation may be mixed-case. Input is lower-cased by the schema, so only those legacy rows are hit — and they are exactly the accounts `auth.py:277` and `admin.py:93` still resolve. Result: sharing to a legacy mixed-case account returns 404 "Recipient not found" while login for it works | `shares.py:104` vs `models/user.py:36-42`, `auth.py:277`, `admin.py:93` |
| L8 | `base64.b64encode(share.wrapped_key)` unguarded against `None` (nullable in the model, non-null in the API contract) | `files.py:498,579` |
| L9 | `_dummy_hash()` lazy init is racy under concurrency; `get_current_user_mfa_verified` fails open on decode errors | `auth.py:72-85`, `deps.py:116-120` |
| L10 | Search walks the `prev_token` chain with one query per hop inside a `while` loop — an O(n) DB round-trip amplifier per request, bounded only by a `visited` set | `search.py:68-84` |
| L11 | No audit-coverage policy: `files.py` audits only `upload`, `download`, `delete`, `restore` — `GET /files` (312), `POST /files/batch` (385), `GET /files/deleted` (435) and `GET /files/{id}` metadata (461) are silent, as are all of `/user/index_state` and `/search` | `files.py:115-116,312,385,435,461,524-525,722-723,772-773`, `user.py:26-53` |
| L12 | `security_headers.py:52-53` adds HSTS whenever `APP_ENV=prod`, even in the compose stack that terminates no TLS (browsers ignore it, but the docstring claims the opposite intent); the Next.js app sets **no** security headers/CSP of its own | `security_headers.py:40-57`, `next.config.ts` |
| L13 | Rate-limit 429 responses bypass `SecurityHeadersMiddleware` and hard-code `retry-after: 60` regardless of configured rate | `rate_limit.py:117-135`, `main.py:142-148` |
| L14 | Skeleton/quality: `FileSystemStorage()` executes `mkdir` at **import** time (`storage/__init__.py:200`) with the default `/var/vaultx/storage` — a non-Docker host without that path gets a `PermissionError` traceback at startup instead of a config error; `STORAGE_DIR`, `MAX_UPLOAD_BYTES`, `LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_SECONDS`, `RATE_LIMIT_MAX_BUCKETS`, `TRUSTED_PROXY_CIDRS` are all missing from `sample.env` | `storage/__init__.py:28,200`, `sample.env` |
| L15 | Dead frontend modules/assets: `hooks/useTransferController.ts` (82 lines, never imported), `config/index.ts` (never imported), `publicRuntimeConfig` (App-Router no-op), unused imports flagged by eslint in 6 files, `errorMessage` duplicated between `lib/types.ts` and per-component helpers | eslint output, import graph |
| L16 | Repository hygiene: `git` `main` has **zero commits** and there is **no root `.gitignore`**, while `d:\vaultx-master\.env` (secrets), `backend/vaultx.db`, `backend/test_keys/`, `backend/test_storage/` and both lockfiles sit untracked at the root — the first `git add .` commits credentials and artefacts | `git status`, `Get-ChildItem -Force` |
| L17 | `Base.__repr__` interpolates **every** column of a model — `password_hash`, the `enc_*` key bundles, `mfa_secret_encrypted` — into its string form, and the JSON log formatter serialises arbitrary `extra` values with `json.dumps(..., default=str)`; `to_dict()` right beside it is dead code. Nothing logs a model instance today (all sites log `str(user.id)`), so this is latent rather than live — but any debug print, exception message or future `extra={"user": user}` writes a user's full secret material to the log | `models/base.py:37-43`, `logging.py:39-65` vs `auth.py:223,354,365` |
| L18 | `lib/api.ts` decides "session expired" by comparing the response `detail` to the **exact English string** `"Invalid or expired token"`, so any other 401 — e.g. `deps.py:127`'s `"MFA verification required for this action"` — surfaces as a generic error and leaves the user half-authenticated with no reset. Recovery is also a hard `window.location.href` navigation (full reload) rather than a router transition, and `hooks/useAuth.ts:17-30` accepts any stored string as a live session, so an expired token renders the dashboard shell before the first call fails. The check couples client behaviour to server error copy | `api.ts:26-30,56-60,91-97,129-133`, `deps.py:127`, `hooks/useAuth.ts:17-30` |

---

## 6. Items inspected and found sound (avoid re-litigating)

These looked suspicious but are correct — recorded so the fix effort is not wasted:

* **CORS will not break the shipped deployment's `Range` header**: `api.getRaw` sends the range **both** as a query parameter and as a header (`file-manager.tsx:346-352`), and the backend reads the query parameter (`files.py:534`), so range download/resume works same-origin through the Next rewrite.
* **`FileShare.wrapped_key` / `File.file_iv` etc. are `nullable=False`** in the model (`models/file.py:59-63,107`), so the unguarded `base64.b64encode(...)` calls are safe today (still brittle — L8).
* **Chunked uploads do not duplicate `IndexEntry` rows**: although the client re-sends `tokens_json` with *every* chunk (`upload-modal.tsx:537`), token rows are only inserted after the `if not upload_complete: return` guard (`files.py:238-241,285-300`), so the composite PK `(token, owner_id)` never collides.
* **Keys *are* rehydrated from `sessionStorage` after a reload** — `login-form.tsx:87-91` writes them, so downloads/uploads read the values they expect (the criticism in M2 is about XSS exposure vs. the stated design, not about missing values).
* **Audit-chain verification is genuinely sound**: `_chain_hash` binds content + `prev_hash` (`audit_log.py:53-63`), signatures are RSA-PSS over the entry hash, `_lock_user_chain` serialises appends per user, the retry loop handles `IntegrityError` forks, and the signed `AuditChainAnchor` detects tail truncation that a hash chain alone cannot (`audit_verify.py:97-164`).
* **The server signing key is created race-safely and never silently rotated** (`server_keys.py:180-232` — `O_EXCL`, mismatch detection, half-pair refusal). Only the *deployment* loses it (H9).
* **Refresh-token reuse detection and rotation are correctly implemented** (`auth.py:693-766`): the jti hash is persisted, rows are locked `FOR UPDATE`, reuse revokes the whole family.
* **`bcrypt` is pinned `<4.1` in `pyproject.toml`**, avoiding the passlib/bcrypt 4.1+ incompatibility, and `hash_password` explicitly rejects >72-byte input instead of letting bcrypt truncate it silently.
* **`tsc --noEmit` passes** — the frontend is type-clean today; the `ignoreBuildErrors` switch (M12) is latent risk, not an active failure.
* **Registration bootstraps keys correctly** — a newly registered user *does* end up with working session keys: `/auth/register` returns `keys=_keys_response(user)` (`auth.py:225-228`), and `login-form.tsx:57-101` runs one shared success path for both `login` and `register`, so the `sessionStorage` writes and the `index_state` unwrap happen after registration too. (This looked like a C4 sibling bug until the register response was checked.)
* **`admin.py` resolves emails the right way** — `create_user` normalises the address and queries with `email_matches()` (`admin.py:90-93`), which is exactly the pattern `shares.py:104` omits (L7). `/auth/login` does the same (`auth.py:277`), including `_dummy_hash()` to equalise timing for unknown accounts (`auth.py:75-85,282`).
* **The MFA settings screen is complete and reachable by normal users** — `mfa-settings.tsx` is mounted from both `file-manager.tsx:632` and `dashboard/admin/page.tsx:472`, backup codes are hashed and single-use (`models/user.py:71-77`), and the numeric inputs are sanitised (`mfa-settings.tsx:12,298`).
* **`useAuth` + `dashboard/page.tsx:18` compose correctly** — the hook issues `router.replace("/")` when no token is stored (`hooks/useAuth.ts:17-31`) and the page returns `null` only in the frame before that redirect; it is not a blank-screen bug. The only weakness is the absence of an expiry check (L18).
* **`POST /files/batch` is read-only** (`files.py:385-390`) — it lists files by ID, so the fact that it is not MFA-gated is a policy gap (M16), not a way to mutate data.

---

## 7. Suggested remediation order

1. **C1** (upload IV) and **C2** (`setVaultXContext`) — until these are fixed the product cannot round-trip a single file, so nothing else is testable end-to-end.
2. **C3 + C4** (MFA bypass and MFA key bootstrap) — one is a security hole, the other makes MFA accounts unusable; they must be fixed together because the fix for C3 removes the accidental workaround for C4.
3. **H1** (delete/restore data loss) then **H3/H4** (share-link correctness and access-code hardening).
4. **H5/H6/H9** (deployability: Python version, declared dependencies, signing-key volume) — these block any real deployment regardless of code quality.
5. **H7/H8** (Redis-backed state, trusted proxies) — required before scaling past one worker.
6. **M12 first among the mediums** (add a pytest suite + a real `tests/` directory + CI, and stop ignoring build errors) so the fixes above are regression-protected.
7. Then the remaining mediums/low items, grouped by file to minimise churn — starting with the three that decide *what the other fixes look like*: **M18** (settle the KDF/bundle-version contract before touching any key handling), **M16** (replace the one-endpoint, process-local MFA gate with a token claim or Redis, applied by policy) and **M17** (implement or delete the `permissions` field). **M10(c)** (admin-created accounts that cannot log in) and **L7** are small, self-contained correctness fixes in the same files.

**Test coverage to add with the fixes:** an end-to-end upload→download round-trip at 4 MB and 12 MB (catches C1 and the chunk framing), an MFA login flow asserting that a pending token is rejected by `/files` (catches C3) and that keys are present afterwards (C4), a soft-delete→restore→download test (H1), a share-link-without-code round-trip (H3), and a `verify_audit_chain` test across a key regeneration (H9).

Also worth adding with M16/M18: a test that a pending MFA token is rejected by a *second* endpoint (e.g. `POST /shares` or `DELETE /admin/users`, not just the one route that happens to be gated today), and a registration→login test asserting the client sends and honours `kdf_iterations`/`key_bundle_version`.

---

## 8. Review coverage and method

* **Scope covered:** all 94 hand-written sources — every `backend/app/**/*.py` and every `frontend/**/*.ts(x)` excluding `node_modules`, `.next`, `__pycache__` and generated `.d.ts`. Deployment/manifest files (`Dockerfile`, `docker-compose.yml`, `pyproject.toml`, `requirements.txt`, `uv.lock`, `sample.env`, `next.config.ts`) and the lockfiles were inspected for H5/H6/H9/L12/M13/M15/L16.
* **Read but deliberately not itemised:** the 15 shadcn/ui primitives (`components/ui/*`) and the presentational components (`file-icon`, `file-skeleton`, `empty-state`, `error-state`, `sort-select`, `view-toggle`, `sidebar`, `badge`, `avatar`). They contain no security-relevant logic — verified by grep: **no** `dangerouslySetInnerHTML`, `eval(`, `new Function(` or `innerHTML` anywhere in the frontend, and **no** `fetch(` outside `lib/api.ts`. (`mfa-settings.tsx` is reachable from both `file-manager.tsx:632` and `dashboard/admin/page.tsx:472`, so MFA setup is not admin-only — that looked like a finding and is not one.)
* **Second pass (this revision).** A coverage sweep against the report text showed that basename matching hides files whose names are substrings of other citations (`page.tsx`, `layout.tsx`, `__init__.py`), which had left `app/layout.tsx`, `app/page.tsx`, `app/dashboard/page.tsx`, `lib/crypto/keys.ts`, `lib/crypto/setupUserKeys.ts`, `hooks/useAuth.ts`, `mfa-settings.tsx` and `schemas/share.py` unreviewed. Those were then read in full, together with `core/security.py`, `models/{base,user}.py` and the login/registration flow end-to-end. Outcome: **new** M16–M18 and L17–L18, and **three corrections** to earlier text — C3's affected-endpoint list (deletion *is* MFA-gated, nothing else is), M10(c) (admin-created accounts cannot log in at all, they do not merely lack keys) and L7 (the citation was `shares.py:104`, and only pre-normalisation rows are affected).
* **Tooling note:** `Select-String -Path <directory> -Include …` silently matches nothing unless the path is enumerable — every grep behind a finding was re-run via `Get-ChildItem -Recurse | Select-String`, and the route inventory was enumerated explicitly rather than inferred. All `file:line` citations in this revision were re-validated against the working tree after editing.


