# VaultX

VaultX is a full-stack secure storage platform built to demonstrate how encrypted cloud storage, searchable data, and tamper-proof auditing can coexist in a single system.
It includes a FastAPI backend, a Next.js frontend, and a PostgreSQL database.
All encryption and verification are handled by the application itself — no third-party encryption services or external key managers are used.

---

## Overview

VaultX implements an **encrypted cloud storage architecture** where every piece of data stored on the server—files, logs, and user information—is encrypted using AES-256-GCM.
It provides encrypted search through hashed keywords, tamper-proof activity logging, and role-based access control for multi-user environments.

The project is designed as a real, working model of a privacy-first storage system, suitable for academic study, internal enterprise deployment, or as a base for production-grade secure applications.

---

## Architecture

VaultX is composed of three primary components:

| Layer    | Technology           | Role                                                              |
| -------- | -------------------- | ----------------------------------------------------------------- |
| Frontend | Next.js + TypeScript | User interface for file upload, management, and search            |
| Backend  | FastAPI (Python)     | Core logic, encryption, file handling, authentication             |
| Database | PostgreSQL           | Persistent storage for encrypted metadata, logs, and user records |

Data flow:

1. The frontend communicates with the FastAPI backend over HTTPS.
2. Files and user data are processed server-side and encrypted before persistence.
3. The PostgreSQL database never stores plaintext; all sensitive fields and blobs are encrypted.

---

## Security Model

### File Encryption

Files are encrypted in 64 KB chunks using **AES-256-GCM**.
Each chunk is assigned a unique random 12-byte nonce, ensuring that even identical file data never produces the same ciphertext.

* Streamed encryption avoids high memory usage on large files.
* GCM mode provides both confidentiality and integrity.
* The backend handles encryption and decryption transparently.

### Data Segmentation

VaultX uses distinct keys for different data categories, derived deterministically from the application’s master key:

```
APP_LOGS_KEY   = SHA256(APP_SECRET_KEY + "LOGS")
APP_EMAILS_KEY = SHA256(APP_SECRET_KEY + "EMAILS")
```

This isolates encryption domains, preventing cross-data compromise even if a specific key is exposed.

### Keyword-Based Search

VaultX allows searching over encrypted files without exposing plaintext keywords.
When a user tags or indexes a file with keywords, each term is transformed using SHA-256 and stored as a digest.

```
hash_keyword(keyword) = SHA256(keyword)
```

At search time, the same transformation is applied, allowing deterministic comparison on hashed values.
This approach enables efficient encrypted search with the tradeoff of equality leakage.

### Tamper-Proof Logging

All API actions (uploads, downloads, deletions, permission updates, searches) are encrypted using **AES-256-GCM** with the logs key.
Each log entry includes an optional hash link to the previous entry, forming a verifiable chain.

This design ensures:

* Encrypted, non-readable logs
* Detection of any modification or deletion
* Replay-resistant audit trails

---

## Cryptographic Components

| Function              | Algorithm                | Details                                                         |
| --------------------- | ------------------------ | --------------------------------------------------------------- |
| File encryption       | AES-256-GCM              | Per-chunk 64 KB encryption with random 12-byte nonce            |
| Log encryption        | AES-256-GCM              | Derived from master key with SHA-256(APP_SECRET_KEY + "LOGS")   |
| Email encryption      | AES-256-GCM              | Derived from master key with SHA-256(APP_SECRET_KEY + "EMAILS") |
| Keyword hashing       | SHA-256                  | Deterministic search index                                      |
| Constant-time compare | secrets.compare_digest   | Prevents timing-based comparisons                               |
| Key generation        | AESGCM.generate_key(256) | Random 256-bit symmetric keys                                   |

All AES-GCM operations authenticate data, providing both confidentiality and integrity.

---

## System Behavior

* Plaintext data never touches disk or the database.
* Every encrypted record can be verified for authenticity upon decryption.
* The application can search, list, and log events without compromising user privacy.
* PostgreSQL only stores ciphertext and hashes.
* The frontend never directly handles keys or performs cryptographic operations; the backend does.

---

## Design Intent

VaultX was built as a **complete demonstration of encrypted infrastructure** — not just a backend service.
It shows how a secure file vault can handle storage, search, access control, and auditing in a single cohesive stack.
The system prioritizes verifiability, isolation of cryptographic domains, and low operational complexity.
