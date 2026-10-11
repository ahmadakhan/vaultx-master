# VaultX security and architecture review

Date: 2026-10-11. Scope: current working tree based on `1eed17c`, not just the initial commit. Numerous modifications and tests predated this review and were preserved. This report does not supersede the existing AUDIT_REPORT.md.

The final status also showed additional deployment/dependency files and SECURITY_REMEDIATION.md changing outside this task. Those changes are not attributed to this review or certified by its checks. This was a live working-tree review, not an immutable release snapshot; freeze and revalidate the release candidate before relying on it.

## Decision and assurance boundary

**Do not deploy this implementation under the requested zero-knowledge, multi-tenant, multi-gigabyte/mobile assurance claims.** The review found a critical server-knowledge flaw, legacy guest confidentiality failures, absent tenant/RLS and passkey infrastructure, and non-streaming downloads. Focused fixes below improve existing behavior; they do not close the architectural gaps.

This is a source review plus bounded synthetic frontend tests, not an exhaustive penetration test, formal proof, dependency certification, deployment inspection, or SOC 2/HIPAA/GDPR assessment. No production database, private environment files, or stored keys were read. Absence findings apply to the inspected application paths, not externally deployed infrastructure.

Security is conditional on trusted endpoint code, operating system, entropy, authenticated identity/key binding, cryptographic assumptions, and correct deployment. Browser code delivered by a malicious application server can steal plaintext before encryption. Neither Web Crypto nor JavaScript provides register erasure or reliable erasure of immutable strings, engine copies, swap, or crash dumps. Hardware-backed platform authenticators are compatible with forbidding external tokens, but are themselves hardware-backed components.

## Architecture & security scorecard

These are evidence-based acceptance verdicts, not invented numerical probabilities of compromise. **0/6 pillars fully satisfied** is a requirements count, not a vulnerability probability.

| Pillar | Verdict | Present | Blocking gap |
|---|---|---|---|
| 1. PQ resilience and blindness | Fail | Client AES-256-GCM, per-file random keys, bounded chunk IV counters, encrypted names | Unlock password sent to backend; RSA-only sharing; no padding; no guaranteed erasure |
| 2. Software MFA and passkeys | Partial / fail | TOTP, persistent attempt budgets, single-use step markers, revocable sessions | No WebAuthn; MFA optional; no independent device-bound encryption factor |
| 3. Resumable transfers | Partial / fail | Bounded file slicing, filesystem streaming, chunk-order checks, owner-scoped staging | Whole-file download buffers; no offset discovery/idempotent retries/tus; Stop is local |
| 4. Mobile lifecycle | Fail | Memory-only session reduces durable local key exposure | No native transfer workers or secure checkpoint/keystore flow; reload loses session |
| 5. Tenancy/RLS | Fail | Application owner/recipient predicates and signed session validation | No tenant model, tenant claim, RLS policies, or transaction-local tenant context |
| 6. Guest inbound uploads | Not implemented / fail capability | Guest download routes; ordinary uploads require authenticated users | No separate write-only guest capability or dropbox protocol |

### Mathematical statements that the implementation supports

* For fixed nonce prefix `p`, chunk IVs are `p[0:8] || uint32_be(i)`. The mapping is injective for `0 <= i < 2^32`. This proves only within-stream counter uniqueness, not all-purpose uniqueness under a key across streams or metadata operations.
* The upload client generates fresh 256-bit file keys. Random key collisions are probabilistic, not impossible (birthday approximation `q(q-1)/2^257` for q independent keys). Metadata and chunks currently share a file key and do not have disjoint nonce domains; random metadata IVs can theoretically overlap chunk IVs. Separate derived subkeys eliminate this particular cross-purpose overlap.
* With fixed plaintext chunk size B and no padding, ciphertext length is `C = P + 16 * max(1, ceil(P/B))`. The server observes C and the number of chunks; it can recover P. Encrypting a JSON size field does not hide the raw size.
* Client upload content processing is bounded in file length for a fixed chunk size, but base64 conversions add copies and CPU overhead. Guest download retains ciphertext chunks, a combined ciphertext buffer, full plaintext, and a Blob: memory is Theta(P), not O(1).
* GCM authenticates each chunk under its key/nonce. Whole trailing-chunk truncation needs trusted authenticated expected size or a final manifest; individual tags alone do not establish stream completeness. Tests verify supplied expected-size enforcement, not a formal cryptographic proof.

## Vulnerability registry

Severity includes failures against the requested threat model. Missing capabilities are explicitly distinguished from demonstrated exploit paths. Locations refer to named functions or stable source ranges; modified line numbers may shift.

| ID | Severity / status | Evidence and trigger | Impact / correction |
|---|---|---|---|
| V01 | **Critical — open** | `frontend/components/login-form.tsx:86-95,139-151` sends `password` to login/register and uses it to prepare/unlock the bundle; `backend/app/api/routers/auth.py:200-249` receives it | A compromised backend captures the vault-unlock secret and decrypts stored bundles. Use an independent unlock secret never sent to the server, or a professionally reviewed PAKE-based architecture with a separately specified vault-key derivation. Migrate existing bundles; changing only login transport is insufficient. |
| V02 | **Critical — legacy exposure open** | `frontend/lib/crypto/passphrase.ts:81-87`; guest page `decryptFileMetadata` falls back to a passphrase derived from public file ID, or access code | Legacy public-ID wraps are decryptable from server/DB data. Legacy code-derived wraps expose the encryption factor to the API when submitted. Revoke and rewrap affected links with independent random fragment secrets; assess whether file-key/content rotation is required. New fragment wraps are not this flaw. |
| V03 | **High — architectural gap** | `backend/app/db.py:42-52`, owner-based file models/routes, `core/deps.py:30-81`; application search found no tenant/RLS integration | A missing application predicate has no tenant-level DB backstop. No tenant-to-tenant isolation proof is possible. Introduce tenant membership, tenant-scoped constraints, forced RLS, constrained roles and transaction-local validated context before claiming multi-tenancy. This is not evidence of a specific current owner-IDOR exploit. |
| V04 | **High — open** | `frontend/lib/crypto/keys.ts:42-60`, public-key lookup in `auth.py:464-482`, sharing wraps recipient keys supplied by backend | RSA-4096 is not PQ-resistant; no authenticated key transparency/out-of-band identity pinning was established. A malicious key directory can substitute a recipient key. Adopt reviewed versioned authenticated hybrid ML-KEM + classical KEM with identity verification and downgrade protection; do not invent a combiner. |
| V05 | **High — open** | Upload metadata/content encryption has no padding; `files.py:264-323`, guest metadata `shares.py:537` expose/log ciphertext length | Exact raw length can be reconstructed; metadata lengths, timing, search links and access patterns leak. Pad content records and metadata in a versioned format, state allowed bucket leakage, minimize logs. Padding cannot hide all traffic patterns. |
| V06 | **High — open** | `frontend/app/shared/[token]/page.tsx:156-217`, `decryptChunkedGCM` full output allocation | Multi-GB files exhaust browser/mobile memory. Use incremental framing/decrypt to a bounded sink; verify completion before exposing a committed output. Retaining all plaintext in isolated memory is incompatible with O(1) memory. |
| V07 | **High — open** | `backend/app/storage/__init__.py:84-85` rejects repeat chunks; no upload offset/status route in `files.py` | A lost acknowledgement strands a valid upload: retransmission conflicts. Implement durable upload state, compare-and-swap offsets, identical-retry semantics, finalization receipts and authenticated status lookup. Client must never re-encrypt changed data under a reused key/index. |
| V08 | **High — open** | `files.py:305-314` flushes DB, publishes filesystem blob, then commits; storage finalization removes staging | Crash/DB-commit failure leaves a blob without a committed row and no resumable staging. Non-overwriting publication then blocks retry. Use durable finalizing states/outbox reconciliation and crash-injection tests, not an assumed cross-filesystem/DB transaction. |
| V09 | **High — open** | `FileSystemStorage.write_chunk` enforces per-upload bytes but no aggregate tenant/user quota, expiration or staging janitor; API parses multipart before handler validation | Many partial uploads and multipart spools can exhaust disk; abandoned lock inodes accumulate. Enforce ingress body limits, per-principal reservations/concurrency, staging TTL, disk quotas and reaping. Deployment ingress limits were not inspected. |
| V10 | **High — missing control** | `auth.py` implements password/TOTP routes, no WebAuthn code found; `deps.py:132-133` permits unenrolled users | Requested passkeys and mandatory MFA are absent. Implement one-time server challenges, RP ID/origin/type/signature/UV verification and replay protection through a vetted library; enrollment/recovery need equal assurance. |
| V11 | **High — missing control** | `frontend/hooks/useAuth.ts:18-29`, memory-only context; no native worker/keystore integration found | OS termination loses keys and transfer state. Browser background execution is not a substitute for WorkManager/iOS background transfer APIs. Use native platform adapters, encrypted resumable checkpoints and explicit re-unlock policy. OS completion still cannot be guaranteed. |
| V12 | **High — threat boundary open** | `frontend/next.config.ts:11-13` lacks script-src; secrets exist as JS/base64 strings | XSS, malicious dependencies or server-delivered JS can exfiltrate live secrets. No XSS exploit was demonstrated. Add Next-compatible nonce CSP, dependency/release controls and a trusted-client distribution strategy for the malicious-server threat. Non-extractable keys still permit use by same-origin malicious JS. |
| V13 | **Medium — fixed narrowly** | Old `decryptChunkedGCM` retained prior plaintext after later-tag failure | Now clears accumulated output on failure and temporary plaintext after copying; rejects malformed framing and counter overflow, returns generic errors. This is best-effort owned-buffer cleanup only. Successful output is caller-owned. |
| V14 | **Medium — fixed locally** | Upload callback state could be stale; abort was not wired into API; stopped state could be overwritten | Added synchronous worker/state coordination, pausing status and acknowledged-cursor resume. Stop remains local: an in-flight request may complete and uploaded server data is not deleted. No cross-tab or durable protocol guarantee. |
| V15 | **Medium — fixed** | Client generated 16-byte search tokens; `files.py:204-210` requires 32 bytes | Keyword-bearing uploads rejected by backend. Client now emits 32-byte tokens; regression verifies payload length. Existing 16-byte chain heads may require rebuilding/migration. |
| V16 | **Medium — open** | Guest `loadMetadata` requests without code; server `_check_access_code` rejects; page `243-263` renders terminal error and code-submit requires metadata | Code-protected links cannot reach the normal unlock form on first load. Provide a non-sensitive access-code-required response/UX independent of metadata; test full protected guest flow. |
| V17 | **Medium — open** | `shares.py:611-618` consumes download quota per request before streaming | Interrupted and ranged downloads each consume a use; a one-download link cannot resume after interruption. Use bounded download-session reservations with explicit retry/accounting semantics; limits cannot prevent saving already-released plaintext. |
| V18 | **Medium — open** | `files.py:353-394` loads all owned/shared rows then sorts/slices | SQL pagination parameters do not bound query/result memory. Push union/order/limit/count into DB; test high file/share cardinality. |
| V19 | **Medium — open protocol binding gap** | Chunk calls use AES-GCM without AAD; metadata lacks tenant/file ID binding; `expectedSize` remains optional | No explicit authenticated tenant/file/version/final-record context; consistent whole-object replay/substitution is not excluded by chunk tags. Introduce canonical AAD and a versioned authenticated manifest; require trusted completeness data in all new-format reads. Preserve explicit legacy handling. |
| V20 | **High — missing capability, not enabled exploit** | Public routes in `shares.py` only serve reads; `files.py` upload requires `get_current_user` | Requested write-only dropboxes do not exist. Do not route guests through ordinary tenant credentials. Introduce narrowly scoped create-only capabilities with private staging, quotas, TTL, immutable object allocation, no list/get/delete/overwrite authority. |

TOTP positives: `auth.py:140-197` uses constant-time code comparisons, persistent unique consumption markers, and user locking; challenge sessions are checked and consumed. Attempt reservations are persistent. These are source-confirmed protections, not PostgreSQL-concurrency verification. The matching loop exits early by matched time step, so no whole-routine constant-time claim is warranted. TOTP is phishing-susceptible; it authenticates server access, not client decryption. Backend compromise and database-only compromise are distinct: an offline DB thief can guess bundle passwords; an active backend can capture the actual password under V01.

## Blueprint corrections required before integration

### 1. Client crypto engine

Do not copy the proposed blueprint verbatim. Its deterministic tenant salt makes identical passwords within a tenant derive identical keys; use random per-account salts with versioned parameters and domain-separated tenant/account context. PBKDF2-600k is a work factor, not a guarantee against weak passwords. Preserve explicit legacy KDF parameters when migrating.

The blueprint's `carry >>= 8` applies signed 32-bit coercion to JavaScript numbers; it is not general 96-bit counter arithmetic. It also omits bounds and overflow rejection. Incrementing random base IVs under a reused master key creates ranges that can overlap. Use a fresh per-file key and bounded counters, with separate derived keys for metadata, content and wraps, and ensure retry semantics do not re-encrypt different plaintext at an already-used index. Authenticate protocol version, tenant ID, file ID, stream identity, index, chunk length and finality using unambiguous canonical encoding. Encryption is O(B) memory only if callers feed and release bounded chunks and sinks apply backpressure; the class alone does not prove this.

Authenticate the final manifest with expected padded record count, true encrypted length, and explicit format version. Enforce resource limits on metadata before allocating output. Store no unwrap secrets server-side. AES-256 offers a strong symmetric margin against idealized Grover search, but does not turn RSA sharing into a PQ protocol. ML-KEM integration requires vetted implementations, authenticated identity binding, supported client builds, versioned envelopes and downgrade tests, not a renamed RSA wrapper.

### 2. PostgreSQL RLS

The provided SQL contains a syntax error: PostgreSQL uses `ENABLE ROW LEVEL SECURITY`, not `ENABLE ROW-LEVEL SECURITY`. Even corrected, it is not a complete isolation design:

* Table owners normally bypass RLS unless forced; superusers and BYPASSRLS roles bypass it. Use a separate migration owner and a constrained runtime role. Force RLS on all relevant tenant tables and verify effective privileges.
* Permissive policies combine with OR. Scope tenant and guest policies to intended roles; keep guest reads separate from tenant writes, with explicit `WITH CHECK` conditions for writes. A matching guest signature should never grant UPDATE/DELETE or tenant enumeration.
* The tenants table and dependent rows need policies/constraints too. Composite tenant foreign keys prevent cross-tenant relationship references. Test backup, administrative, search, audit and background-worker paths, not only metadata listing.
* Derive tenant context from verified session and membership, not arbitrary request input. Use parameterized `set_config(..., ..., true)` inside the same transaction/connection as protected queries. Any commit ends local context; current routers commit mid-flow, requiring careful transaction redesign.
* A custom GUC is context, not an unforgeable identity. Application roles that can execute arbitrary SQL can generally set their context. RLS protects missing predicates, not unrestricted SQL execution by a compromised trusted service. Pool-reuse, absent/malformed context, cross-tenant writes, roles, and concurrent requests need real PostgreSQL tests.

No SQL migration was applied: the current schema has no tenant identity to backfill, and selecting a migration rule without product decisions could corrupt access rights.

### 3. Guest hash anchors and write-only dropboxes

New share creation uses independent random fragment secrets and client-side wrapping; existing frontend tests verify that server-known file IDs/access codes cannot decrypt those new wraps. URL fragments are excluded from HTTP request targets and referrers, but remain accessible to page scripts, extensions, screenshots, copied URLs and some browser history/sync mechanisms. Do not send them in telemetry or APIs; capture then remove from the address bar where the reloading/recovery UX permits, prohibit third-party scripts, and set no-store/referrer policy. Path bearer tokens still require log redaction and expiry. Revoke legacy wraps rather than treating compatibility as zero-knowledge.

For dropboxes, authenticate the tenant recipient encryption key to the uploading client; otherwise server key substitution defeats inbound confidentiality. Guest capabilities should authorize only new opaque uploads in private staging with server-assigned identities, byte/time budgets and single-use finalization. Distinct read capabilities must never be derived from write capabilities. Test that guest credentials cannot invoke list, read, range, overwrite, metadata mutation, share creation or deletion endpoints.

### Conflicting or unattainable requirements

* A server without the file key cannot verify the file's symmetric GCM authentication tag. Verify tags on clients. TLS protects transport; server-side ciphertext checksums can detect accidental storage changes, but an untrusted server can replace checksums. A signed ciphertext manifest can provide public verification under a separately authenticated verification key without releasing decryption keys.
* Literal “all cryptographic operations client-side” conflicts with TLS, JWT signatures, password verification and server-side TOTP validation. The implementable requirement is that **all file/metadata encryption and unwrapping secrets remain client-only**, while authentication cryptography is separately permitted and threat-modeled.
* `authenticatorAttachment: "platform"`, internal transport hints and `userVerification: "required"` guide WebAuthn enrollment but do not universally prove a non-exportable hardware-keystore credential. Synced passkeys, backup flags and attestation policies must be addressed. Assertions must verify stored credential policy and actual UV, challenge, origin and RP ID; hints are not a security proof. PRF support, if used to wrap local keys, requires capability checks and a secure recovery strategy. Do not mix rolling TOTP values into a permanent file key.
* O(1)-memory multi-gigabyte decryption cannot also retain the entire assembled plaintext solely in memory. Select a supported streaming sink or explicitly reject oversized downloads; browser file-system support differs by platform.
* iOS/Android schedulers may defer or terminate work. Aim for durable, recoverable state and bounded exposure, not guaranteed uninterrupted background execution.
* SOC 2 requires operating control evidence/attestation; HIPAA requires risk analysis, administrative/physical safeguards and applicable agreements; GDPR requires lawful processing, minimization, rights handling, retention and accountability. Encryption alone proves none of these. No compliance certification is asserted here.

## Refactored source delivered

Complete edited source files are in the workspace, not abbreviated snippets:

1. `frontend/lib/crypto/chunking.ts`: framing validation, explicit counter bound, authenticated expected-size checks, generic decrypt failure and best-effort temporary/failed-output cleanup.
2. `frontend/components/upload-modal.tsx`: correct 32-byte search tokens, synchronous worker exclusion, chunk-boundary pause, cursor-preserving resume, terminal stopped-state protection, scoped errors and best-effort owned raw-key/plaintext buffer cleanup.
3. `frontend/tests/chunking.test.cjs`: real Web Crypto roundtrips/tampering/truncation and isolated observable cleanup tests.
4. `frontend/tests/upload-modal.test.cjs`: transpiled component callback tests for duplicate starts, pause/resume, stop during preparation/in-flight/final requests, token lengths and buffer cleanup.

These are backward-compatible, bounded improvements, **not a production-ready replacement for the requested architecture**. No new encryption format, tenant migration, passkey enrollment, native mobile runtime or dropbox protocol was fabricated. Legacy full-object decryption remains O(n). Existing weak guest wraps and transmitted vault passwords require migration before assurance claims change.

## Verification receipts and limitations

From `frontend/`:

* `node --test tests/security.test.cjs tests/chunking.test.cjs tests/upload-modal.test.cjs` — **18 passed, 0 failed**.
* `npx tsc --noEmit --incremental false` — **passed**.
* `npx eslint lib/crypto/chunking.ts components/upload-modal.tsx tests/chunking.test.cjs tests/upload-modal.test.cjs` — **passed**.

From repository root: `git diff --check` — passed at verification time. Source search of backend/app and frontend lib/app/components found no tenant_id, RLS policy, WebAuthn, ML-KEM, WorkManager or BGTask integration. This search complements inspected source; it is not proof about every dependency or deployment.

Backend command attempted from `backend/`: `PYTHONPATH=. python -m pytest --noconftest tests/test_storage_security.py tests/test_identity_security.py -q` — blocked (`python` missing). Retried explicitly with `python3` — blocked (`No module named pytest`). No backend test is claimed passed and no dependency installation was performed. Existing backend tests describe synthetic SQLite/stubbed boundaries; even a pass would not establish production PostgreSQL RLS or locking behavior.

Not performed: full production build, full-project lint, live-browser end-to-end tests, protected guest UX test, real PostgreSQL concurrency/RLS tests, memory benchmarks, network-switch/OS-kill tests, crash-consistency injection, deployed storage/IAM/ingress audit, dependency vulnerability scan, external pentest or machine-checked formal verification.

## Prioritized path to release

1. Resolve the malicious-server threat model and remove server knowledge of vault-unlock secrets. Inventory and revoke/migrate legacy guest wraps. Define trusted client distribution and key identity verification.
2. Specify a versioned padded streaming envelope, domain-separated per-file subkeys, authenticated manifest and hybrid recipient sharing. Add migration fixtures and adversarial interoperability tests before deployment.
3. Specify tenant identity/membership/backfill and role separation, then implement RLS with deny-by-default PostgreSQL tests and transaction-pool leak tests.
4. Implement an explicit transfer state machine with durable offsets, idempotent receipts, local single-worker ownership, quota reservations, crash recovery and staging expiration. Model invariants for ownership, immutable sealed chunks, monotonic offsets and exactly-once publication; prove/model-check them separately from implementation tests.
5. Add vetted WebAuthn with platform policy, mandatory MFA/recovery controls and native mobile keystore/background-transfer adapters. Add write-only guest capabilities only after tenant and transfer invariants are enforced.
6. Gate release on live multi-GB memory measurements, lost-ACK/replay/race/crash tests, real PostgreSQL cross-tenant negative tests, mobile process-death recovery, independent crypto review and operational compliance evidence.
