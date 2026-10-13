"""Focused invariants for Phase 5/6 transfer foundations."""

import io
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.schemas.transfer import UploadSessionFinalize
from app.storage import FileSystemStorage


def test_resumable_append_is_bounded_and_monotonic(tmp_path):
    storage = FileSystemStorage(str(tmp_path))
    upload_id = str(uuid.uuid4())
    assert storage.append_stream(upload_id, 0, io.BytesIO(b"abc"), max_bytes=5, max_chunk_bytes=4) == 3
    with pytest.raises(ConflictError):
        storage.append_stream(upload_id, 0, io.BytesIO(b"x"), max_bytes=5, max_chunk_bytes=4)
    with pytest.raises(ValidationError):
        storage.append_stream(upload_id, 3, io.BytesIO(b"12345"), max_bytes=5, max_chunk_bytes=4)
    assert storage.staged_path(upload_id).read_bytes() == b"abc"


def test_dropbox_capability_hash_is_not_reversible_in_storage_model():
    from app.api.routers.transfers import _hash_capability

    capability = "A" * 43
    digest = _hash_capability(capability)
    assert digest != capability.encode()
    assert len(digest) == 32


def test_upload_finalization_payload_is_explicitly_encrypted_metadata():
    payload = UploadSessionFinalize(
        metadata_ciphertext_b64="YQ==",
        metadata_iv_b64="AAAAAAAAAAAAAAAA",
        encrypted_kf_b64="Yg==",
        encrypted_kf_iv_b64="AAAAAAAAAAAAAAAA",
        file_iv_b64="AAAAAAAAAAAAAAAA",
    )
    assert payload.tokens == []
    assert payload.metadata_ciphertext_b64 == "YQ=="


def test_upload_session_tenant_check_rejects_cross_tenant_access():
    from app.api.routers.transfers import _check_tenant

    session = SimpleNamespace(owner_id=uuid.UUID(int=1), tenant_id=uuid.UUID(int=2))
    user = SimpleNamespace(id=session.owner_id, tenant_id=uuid.UUID(int=3))
    with pytest.raises(AuthorizationError):
        _check_tenant(session, user)


def test_guest_dropbox_owner_check_rejects_cross_tenant_or_owner_access():
    from app.api.routers.transfers import _check_dropbox

    dropbox = SimpleNamespace(owner_id=uuid.UUID(int=1), tenant_id=uuid.UUID(int=2))
    with pytest.raises(NotFoundError):
        _check_dropbox(dropbox, SimpleNamespace(id=uuid.UUID(int=9), tenant_id=dropbox.tenant_id))
    with pytest.raises(AuthorizationError):
        _check_dropbox(dropbox, SimpleNamespace(id=dropbox.owner_id, tenant_id=uuid.UUID(int=3)))


@pytest.mark.asyncio
async def test_upload_finalization_requires_complete_session():
    from app.api.routers.transfers import finalize_upload_session

    session = SimpleNamespace(
        id=uuid.uuid4(), file_id=uuid.uuid4(), owner_id=uuid.UUID(int=1),
        tenant_id=None, status="active", offset=1, total_bytes=2,
    )

    class FakeDb:
        def __init__(self):
            self.values = iter((session, None))

        async def scalar(self, _statement):
            return next(self.values)

    with pytest.raises(ConflictError, match="not complete"):
        await finalize_upload_session(
            session.id,
            UploadSessionFinalize(
                metadata_ciphertext_b64="YQ==", metadata_iv_b64="AAAAAAAAAAAAAAAA",
                encrypted_kf_b64="Yg==", encrypted_kf_iv_b64="AAAAAAAAAAAAAAAA",
                file_iv_b64="AAAAAAAAAAAAAAAA",
            ),
            FakeDb(), SimpleNamespace(id=session.owner_id, tenant_id=None),
        )


@pytest.mark.asyncio
async def test_finalization_retry_is_idempotent_without_a_second_quota_reservation(monkeypatch):
    from app.api.routers.transfers import finalize_upload_session

    file_id = uuid.uuid4()
    owner_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    session = SimpleNamespace(
        id=uuid.uuid4(), file_id=file_id, owner_id=owner_id, tenant_id=tenant_id,
        status="finalized", offset=10, total_bytes=10,
    )
    existing = SimpleNamespace(
        id=file_id, owner_id=owner_id, tenant_id=tenant_id,
        created_at=datetime.now(UTC),
    )

    class FakeDb:
        def __init__(self):
            self.values = iter((session, existing))

        async def scalar(self, _statement):
            return next(self.values)

    reserved = False

    async def reserve(*_args):
        nonlocal reserved
        reserved = True

    monkeypatch.setattr("app.api.routers.transfers.reserve_storage", reserve)
    result = await finalize_upload_session(
        session.id,
        UploadSessionFinalize(
            metadata_ciphertext_b64="YQ==",
            metadata_iv_b64="AAAAAAAAAAAAAAAA",
            encrypted_kf_b64="Yg==",
            encrypted_kf_iv_b64="AAAAAAAAAAAAAAAA",
            file_iv_b64="AAAAAAAAAAAAAAAA",
        ),
        FakeDb(),
        SimpleNamespace(id=owner_id, tenant_id=tenant_id),
    )
    assert result.id == file_id
    assert reserved is False
