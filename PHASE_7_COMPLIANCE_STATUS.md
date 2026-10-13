# Phase 7 compliance evidence status

This document records implementation evidence only. VaultX has no independent
certification and this file makes no SOC 2, ISO 27001, GDPR, HIPAA, or other
compliance claim.

## Evidence currently available

- Resumable transfer state is durable in `upload_sessions`; offsets are checked
  under a row lock and request bodies are bounded before persistence.
- Guest inbound dropboxes use opaque random capabilities stored only as SHA-256
  hashes, expire, enforce upload and byte budgets, and expose a write-only POST
  route. There are deliberately no guest read/list/delete routes.
- Native iOS/Android implementations are absent. The frontend exposes explicit
  `SecureKeyStoreAdapter` and `BackgroundTransferAdapter` contracts and the
  default adapter rejects operations rather than silently falling back to
  insecure behavior.

## Outstanding evidence

Production deployment review, independent penetration testing, PostgreSQL
concurrency testing, key-management review, retention verification, and any
formal control mapping remain open. Passing repository tests is not a
certification or compliance attestation.
