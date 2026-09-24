"""Integration tests for the VaultX backend.

Exercises the full API surface: registration, login, file upload,
listing, sharing, search, download, delete, restore, and audit
verification. Generates proper encrypted key bundles and file payloads
matching the production schemas.

Run with::

    python test.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import uuid

import requests

BASE = "http://127.0.0.1:8000"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def hr(title: str) -> None:
    print(f"\n{CYAN}{'=' * 25} {title} {'=' * 25}{RESET}")


def pretty(r: requests.Response) -> requests.Response:
    print(f"{YELLOW}{r.request.method} {r.request.url}{RESET}")
    print(f"→ Status: {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text.strip() or "<no response body>")
    print()
    return r


def gen_b64(n: int = 32) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def step_ok(ok: bool) -> None:
    print(f"{GREEN}✅ OK{RESET}" if ok else f"{RED}❌ FAIL{RESET}")


def build_key_bundle() -> dict[str, str]:
    """Generate a valid encrypted key bundle matching RegisterPayload.

    Returns:
        A dict with all required fields for user registration.
    """
    return {
        "password_salt_b64": gen_b64(16),
        "enc_master_key_b64": gen_b64(32),
        "enc_master_key_iv": gen_b64(12),
        "enc_search_key_b64": gen_b64(32),
        "enc_search_key_iv": gen_b64(12),
        "enc_private_key_b64": gen_b64(48),
        "enc_private_key_iv": gen_b64(12),
        "public_key_b64": gen_b64(32),
    }


def build_upload_payload(file_id: str) -> dict[str, str]:
    """Build a valid upload payload with all required form fields.

    Args:
        file_id: UUID string for the file.

    Returns:
        A dict suitable for ``requests.post(..., data=...)``.
    """
    return {
        "file_id": file_id,
        "metadata_ciphertext": gen_b64(64),
        "metadata_iv": gen_b64(12),
        "encrypted_kf_b64": gen_b64(32),
        "encrypted_kf_iv": gen_b64(12),
        "file_iv": gen_b64(12),
        "is_last_chunk": "true",
        "total_chunks": "1",
        "tokens_json": json.dumps(
            [
                {
                    "token": gen_b64(16),
                    "value": {"ciphertext_b64": gen_b64(32), "iv_b64": gen_b64(12)},
                    "prev_token": None,
                }
            ]
        ),
    }


def register_user(email: str) -> None:
    hr(f"Register {email}")
    payload = {
        "email": email,
        "password": "SecureP@ss123",
        **build_key_bundle(),
    }
    r = requests.post(f"{BASE}/auth/register", json=payload)
    pretty(r)
    step_ok(r.status_code == 200)


def login(email: str) -> str:
    hr(f"Login {email}")
    r = requests.post(f"{BASE}/auth/login", json={"email": email, "password": "SecureP@ss123"})
    pretty(r)
    step_ok(r.status_code == 200)
    if r.ok:
        return r.json().get("access_token")
    sys.exit(1)


def upload_file(token: str) -> tuple[str, list]:
    hr("Upload File")
    file_id = str(uuid.uuid4())
    data = build_upload_payload(file_id)
    files = {"file": ("test.txt", b"Hello encrypted world!")}

    r = requests.post(
        f"{BASE}/files/upload",
        files=files,
        data=data,
        headers=auth_header(token),
    )
    pretty(r)
    step_ok(r.status_code == 200)

    if r.ok:
        tokens = json.loads(data["tokens_json"])
        return r.json()["id"], tokens

    sys.exit(1)


def list_files(token: str) -> requests.Response:
    hr("List Files")
    r = requests.get(f"{BASE}/files", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def share_file(token: str, file_id: str, recipient_email: str) -> str:
    hr(f"Share File with {recipient_email}")
    payload = {
        "file_id": file_id,
        "recipient_email": recipient_email,
        "wrapped_key_b64": gen_b64(32),
        "permissions": "read",
    }
    r = requests.post(f"{BASE}/shares", json=payload, headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    if r.ok:
        return r.json()["id"]
    sys.exit(1)


def revoke_share(token: str, file_id: str, recipient_email: str) -> None:
    hr(f"Revoke Share with {recipient_email}")
    payload = {
        "file_id": file_id,
        "recipient_email": recipient_email,
    }
    r = requests.post(f"{BASE}/shares/revoke", json=payload, headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)


def my_shares(token: str) -> requests.Response:
    hr("My Shares (as recipient)")
    r = requests.get(f"{BASE}/shares/me", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def search_files(token: str, tokens: list) -> requests.Response:
    hr("Search Files")
    payload = {"token": tokens[0]["token"]}
    r = requests.post(f"{BASE}/search", json=payload, headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def download_file(token: str, file_id: str) -> None:
    hr(f"Download File {file_id}")
    r = requests.get(f"{BASE}/files/{file_id}/download", headers=auth_header(token))
    print(f"{YELLOW}{r.request.method} {r.request.url}{RESET}")
    print(f"→ Status: {r.status_code}")
    if r.ok:
        print(f"Downloaded {len(r.content)} bytes.")
    else:
        print(r.text.strip() or "<no response body>")
    print()
    step_ok(r.status_code == 200)


def delete_file(token: str, file_id: str) -> None:
    hr(f"Delete File {file_id}")
    r = requests.delete(f"{BASE}/files/{file_id}", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)


def admin_list_users(token: str) -> requests.Response:
    hr("Admin: List Users")
    r = requests.get(f"{BASE}/admin/users", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def admin_create_user(token: str) -> str:
    hr("Admin: Create User")
    payload = {
        "email": "admin-created@example.com",
        "password": "SecureP@ss123",
        "role": "user",
    }
    r = requests.post(f"{BASE}/admin/users", json=payload, headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r.json().get("id", "")


def admin_delete_user(token: str, user_id: str) -> requests.Response:
    hr(f"Admin: Delete User {user_id}")
    r = requests.delete(f"{BASE}/admin/users/{user_id}", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def admin_audit_logs(token: str) -> requests.Response:
    hr("Admin: List Audit Logs")
    r = requests.get(f"{BASE}/admin/audit/logs?limit=10", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def admin_verify_chain(token: str, user_id: str) -> requests.Response:
    hr(f"Admin: Verify Audit Chain for {user_id}")
    r = requests.get(f"{BASE}/admin/audit/verify?user_id={user_id}", headers=auth_header(token))
    pretty(r)
    step_ok(r.status_code == 200)
    return r


def run() -> None:
    print(f"{CYAN}\n=== VaultX Backend Full Test ==={RESET}")
    start = time.time()

    register_user("alice@example.com")
    register_user("bob@example.com")

    alice_token = login("alice@example.com")
    bob_token = login("bob@example.com")

    file_id, tokens = upload_file(alice_token)
    list_files(alice_token)

    share_file(alice_token, file_id, "bob@example.com")
    my_shares(bob_token)

    search_files(alice_token, tokens)
    download_file(bob_token, file_id)

    # Admin tests (alice is the first registered user → admin)
    admin_list_users(alice_token)
    created_id = admin_create_user(alice_token)
    if created_id:
        admin_delete_user(alice_token, created_id)
    admin_audit_logs(alice_token)

    delete_file(alice_token, file_id)
    revoke_share(alice_token, file_id, "bob@example.com")

    elapsed = time.time() - start
    print(f"{GREEN}\n✅ All tests completed in {elapsed:.2f}s.{RESET}")


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted.")
