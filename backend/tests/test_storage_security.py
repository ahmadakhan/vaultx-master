"""Synthetic storage/router regressions; no settings, keys or live DB are loaded.

Run with PYTHONPATH=. pytest --noconftest tests/test_storage_security.py.
Auth/audit boundaries are stubbed only when loading these two routers. Persistence
uses a fresh in-memory SQLite database and blobs live in pytest's temporary folder.
"""
import asyncio
import base64
import hashlib
import importlib.util
import io
import json
import sys
import types
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.testclient import TestClient
from pydantic import ValidationError as SchemaError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.models import Base, File, IndexEntry, SharedLink
from app.models.file import SharedLinkAttempt
from app.storage import FileSystemStorage
from app.storage.share_security import hash_access_code, verify_access_code


def b64(value):
    return base64.b64encode(value).decode()


@pytest.fixture
def routers(monkeypatch, tmp_path):
    async def dependency():
        return None

    stubs = {
        "app.core.audit_decorator": {"audit_event": lambda *a, **k: lambda f: f},
        "app.core.deps": {"get_current_user": dependency, "get_current_user_mfa_verified": dependency},
        "app.db": {"get_db": dependency},
        "app.config": {"settings": SimpleNamespace(max_upload_bytes=100)},
    }
    for name, attrs in stubs.items():
        module = types.ModuleType(name)
        module.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, name, module)
    # Avoid app.schemas.__init__ importing unrelated auth/config machinery.
    schemas = types.ModuleType("app.schemas")
    schemas.__path__ = [str(Path(__file__).parents[1] / "app/schemas")]
    monkeypatch.setitem(sys.modules, "app.schemas", schemas)
    for name in ("file", "share"):
        spec = importlib.util.spec_from_file_location(
            f"app.schemas.{name}", Path(schemas.__path__[0]) / f"{name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        schemas.__dict__.update({key: value for key, value in vars(module).items() if not key.startswith("_")})
    loaded = []
    storage = FileSystemStorage(str(tmp_path / "blobs"))
    for name in ("files", "shares"):
        spec = importlib.util.spec_from_file_location(
            f"storage_test_{name}", Path(__file__).parents[1] / "app/api/routers" / f"{name}.py"
        )
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, spec.name, module)
        spec.loader.exec_module(module)
        monkeypatch.setattr(module, "get_storage", lambda: storage)
        loaded.append(module)
    return *loaded, storage


async def database():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


def test_storage_rejects_traversal_and_bad_sequences(tmp_path):
    storage = FileSystemStorage(str(tmp_path))
    for identifier in ("../escape", "/tmp/escape", "invalid"):
        with pytest.raises(ValidationError):
            storage.delete_blob(identifier)
    identifier = str(uuid.uuid4())
    for index, total, final in ((-1, 1, False), (0, 0, True), (1, 1, True), (0, 10001, False), (0, 2, True)):
        with pytest.raises(ValidationError):
            storage.write_chunk(identifier, index, total, b"x", final)


def test_storage_aggregate_limit_metadata_and_no_overwrite(tmp_path):
    storage = FileSystemStorage(str(tmp_path))
    identifier = str(uuid.uuid4())
    assert not storage.write_chunk(identifier, 0, 2, io.BytesIO(b"abc"), False,
                                   max_bytes=5, metadata={"iv": "first"})
    with pytest.raises(ValidationError):
        storage.write_chunk(identifier, 1, 2, b"def", True, max_bytes=5)
    assert storage.write_chunk(identifier, 1, 2, b"de", True, max_bytes=5)
    assert storage.upload_metadata(identifier) == {"iv": "first"}
    final = storage.finalize_upload(identifier, identifier)
    assert final.read_bytes() == b"abcde"
    assert storage.write_chunk(identifier, 0, 1, b"replacement", False)
    with pytest.raises(ConflictError):
        storage.finalize_upload(identifier, identifier)
    assert final.read_bytes() == b"abcde"


def test_storage_lock_and_symlink_boundary(tmp_path):
    storage = FileSystemStorage(str(tmp_path / "root"))
    identifier = str(uuid.uuid4())
    with storage.upload_lock(identifier), pytest.raises(ConflictError), storage.upload_lock(identifier):
        pass
    (storage.root / "blobs").symlink_to(tmp_path)
    with pytest.raises(ValidationError):
        storage._final_path(identifier)


def test_salted_hashes_and_legacy_verification():
    first = hash_access_code("123456")
    second = hash_access_code("123456")
    assert first != second
    assert verify_access_code("123456", first)
    assert not verify_access_code("654321", first)
    assert verify_access_code("123456", hashlib.sha256(b"123456").hexdigest())
    assert not verify_access_code("123456", "pbkdf2_sha256$999999999$bad$bad")


def test_share_schema_requires_valid_key_material_and_read_only(routers):
    _, shares, _ = routers
    SharedLinkCreate = shares.SharedLinkCreate
    FileShareCreate = shares.FileShareCreate
    fields = dict(file_id=uuid.uuid4(), encrypted_kf_b64=b64(b"k" * 48),
                  encrypted_kf_iv_b64=b64(b"i" * 12), kf_salt_b64=b64(b"s" * 16))
    assert SharedLinkCreate(**fields)
    with pytest.raises(SchemaError):
        SharedLinkCreate(file_id=uuid.uuid4())
    with pytest.raises(SchemaError):
        SharedLinkCreate(**(fields | {"encrypted_kf_iv_b64": "%%%"}))
    with pytest.raises(SchemaError):
        FileShareCreate(file_id=uuid.uuid4(), recipient_email="guest@example.com",
                        wrapped_key_b64="AA==", permissions="admin")


def upload_fields(file_id, user, db, content=b"abc", **overrides):
    fields = dict(request=None, file_id=str(file_id), current_user=user, db=db,
                  metadata_ciphertext=b64(b"metadata"), metadata_iv=b64(b"m" * 12),
                  encrypted_kf_b64=b64(b"k" * 48), encrypted_kf_iv=b64(b"k" * 12),
                  file_iv=b64(b"f" * 12), tokens_json="[]", chunk_index=0,
                  total_chunks=1, is_last_chunk=False,
                  file=UploadFile(file=io.BytesIO(content)))
    return fields | overrides


def test_chunk_upload_ownership_metadata_and_small_download(routers):
    files, _, storage = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                user = SimpleNamespace(id=uuid.uuid4())
                other = SimpleNamespace(id=uuid.uuid4())
                file_id = uuid.uuid4()
                await files.upload_file(**upload_fields(file_id, user, db, total_chunks=2))
                with pytest.raises(ValidationError):
                    await files.upload_file(**upload_fields(file_id, other, db, b"bad", chunk_index=1,
                                                          total_chunks=2, is_last_chunk=True))
                await files.upload_file(**upload_fields(file_id, user, db, b"def", chunk_index=1,
                                                      total_chunks=2, is_last_chunk=True,
                                                      metadata_ciphertext="", file_iv=""))
                saved = await db.get(File, file_id)
                assert saved.owner_id == user.id
                assert saved.metadata_ciphertext == b"metadata" and saved.file_iv == b"f" * 12
                response = await files.download_file(None, str(file_id), None, db, user)
                assert base64.b64decode(response["ciphertext"]) == b"abcdef"
                with pytest.raises(ConflictError):
                    await files.upload_file(**upload_fields(file_id, other, db))
                await files.delete_file(None, str(file_id), db, user)
                assert storage._final_path(str(file_id)).read_bytes() == b"abcdef"
                with pytest.raises(NotFoundError):
                    await files.download_file(None, str(file_id), None, db, user)
                await files.restore_file(None, str(file_id), db, user)
                response = await files.download_file(None, str(file_id), None, db, user)
                assert base64.b64decode(response["ciphertext"]) == b"abcdef"
        finally:
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("tokens", ['{}', '[{"token":"bad"}]', '[null]'])
def test_upload_rejects_malformed_index_before_writing(routers, tokens):
    files, _, storage = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                file_id = uuid.uuid4()
                with pytest.raises(ValidationError):
                    await files.upload_file(**upload_fields(file_id, SimpleNamespace(id=uuid.uuid4()), db,
                                                          tokens_json=tokens))
                assert not storage._final_path(str(file_id)).exists()
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_link_throttle_persists_and_legacy_hash_upgrades(routers):
    _, shares, _ = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                link = SharedLink(file_id=uuid.uuid4(), token="synthetic",
                                  access_code_hash=hashlib.sha256(b"123456").hexdigest())
                db.add(link)
                await db.commit()
                await shares._check_access_code(db, link, "123456")
                await db.commit()
                assert link.access_code_hash.startswith("pbkdf2_sha256$")
                for _ in range(5):
                    with pytest.raises(AuthorizationError):
                        await shares._check_access_code(db, link, "wrong")
                guard = await db.get(SharedLinkAttempt, link.id)
                assert guard.failed_attempts == 5 and guard.locked_until
                with pytest.raises(HTTPException) as error:
                    await shares._check_access_code(db, link, "123456")
                assert error.value.status_code == 429
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_public_download_limit_range_and_missing_blob(routers):
    _, shares, _ = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                file = File(owner_id=uuid.uuid4(), ciphertext=b"abcdef", file_iv=b"i" * 12,
                            metadata_ciphertext=b"metadata", metadata_iv=b"m" * 12)
                db.add(file)
                await db.flush()
                link = SharedLink(file_id=file.id, token="synthetic", max_downloads=1)
                db.add(link)
                await db.commit()
                with pytest.raises(HTTPException):
                    await shares.download_shared_link_file("synthetic", None, "bytes=9-12", db)
                assert link.download_count == 0
                response = await shares.download_shared_link_file("synthetic", None, "bytes=1-3", db)
                assert response.status_code == 206
                assert response.headers["Content-Range"] == "bytes 1-3/6"
                assert b"".join([part async for part in response.body_iterator]) == b"bcd"
                assert link.download_count == 1
                with pytest.raises(NotFoundError):
                    await shares.download_shared_link_file("synthetic", None, None, db)
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_access_codes_are_header_only(routers):
    _, shares, _ = routers
    app = FastAPI()
    app.include_router(shares.router)
    with TestClient(app) as client:
        schema = client.get("/openapi.json").json()
    for path in ("/shares/link/{token}", "/shares/link/{token}/download"):
        params = schema["paths"][path]["get"]["parameters"]
        assert any(p["name"] == "X-Access-Code" and p["in"] == "header" for p in params)
        assert not any(p["name"] == "access_code" for p in params)


def test_index_conflict_leaves_existing_data_intact(routers):
    files, _, storage = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                user = SimpleNamespace(id=uuid.uuid4())
                first, second = uuid.uuid4(), uuid.uuid4()
                tokens = json.dumps([{"token": b64(b"t" * 32), "value": {
                    "ciphertext_b64": b64(b"reference"), "iv_b64": b64(b"i" * 12)}}])
                await files.upload_file(**upload_fields(first, user, db, tokens_json=tokens))
                original = (await db.execute(select(IndexEntry))).scalar_one()
                with pytest.raises(ConflictError):
                    await files.upload_file(**upload_fields(second, user, db, tokens_json=tokens))
                assert not storage._final_path(str(second)).exists()
                assert (await db.execute(select(IndexEntry))).scalar_one().value == original.value
                assert storage._final_path(str(first)).read_bytes() == b"abc"
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_download_reservation_is_atomic_across_sessions(routers, tmp_path):
    _, shares, _ = routers

    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'synthetic.sqlite'}")
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            async with sessions() as db:
                file = File(owner_id=uuid.uuid4(), ciphertext=b"abc", file_iv=b"i" * 12,
                            metadata_ciphertext=b"metadata", metadata_iv=b"m" * 12)
                db.add(file)
                await db.flush()
                db.add(SharedLink(file_id=file.id, token="race", max_downloads=1))
                await db.commit()

            async def download():
                async with sessions() as db:
                    try:
                        await shares.download_shared_link_file("race", None, None, db)
                        return True
                    except NotFoundError:
                        return False

            results = await asyncio.gather(download(), download())
            assert sorted(results) == [False, True]
            async with sessions() as db:
                link = (await db.execute(select(SharedLink))).scalar_one()
                assert link.download_count == 1
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_link_creation_ignores_untrusted_host(routers):
    _, shares, _ = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                user = SimpleNamespace(id=uuid.uuid4())
                file = File(owner_id=user.id, ciphertext=b"abc", file_iv=b"i" * 12,
                            metadata_ciphertext=b"metadata", metadata_iv=b"m" * 12)
                db.add(file)
                await db.commit()
                payload = shares.SharedLinkCreate(file_id=file.id,
                    encrypted_kf_b64=b64(b"k" * 48), encrypted_kf_iv_b64=b64(b"i" * 12),
                    kf_salt_b64=b64(b"s" * 16), access_code="123456")
                result = await shares.create_shared_link(SimpleNamespace(headers={"host": "evil.test"}),
                                                        payload, db, user)
                assert result.link_url == f"/shared/{result.token}"
                assert result.has_access_code
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_failed_purge_commit_does_not_destroy_blob(routers, monkeypatch):
    files, _, storage = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                user = SimpleNamespace(id=uuid.uuid4())
                file_id = uuid.uuid4()
                await files.upload_file(**upload_fields(file_id, user, db))
                await files.delete_file(None, str(file_id), db, user)

                async def fail_commit():
                    raise RuntimeError("Synthetic commit failure")

                monkeypatch.setattr(db, "commit", fail_commit)
                with pytest.raises(RuntimeError):
                    await files.purge_file(None, str(file_id), db, user)
                assert storage._final_path(str(file_id)).read_bytes() == b"abc"
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_missing_filesystem_blob_does_not_return_empty_success(routers):
    files, shares, storage = routers

    async def scenario():
        engine, sessions = await database()
        try:
            async with sessions() as db:
                user = SimpleNamespace(id=uuid.uuid4())
                file_id = uuid.uuid4()
                await files.upload_file(**upload_fields(file_id, user, db))
                link = SharedLink(file_id=file_id, token="missing", max_downloads=1)
                db.add(link)
                await db.commit()
                storage.delete_blob(str(file_id))
                with pytest.raises(NotFoundError):
                    await files.download_file(None, str(file_id), None, db, user)
                with pytest.raises(NotFoundError):
                    await shares.download_shared_link_file("missing", None, None, db)
                assert link.download_count == 0
        finally:
            await engine.dispose()
    asyncio.run(scenario())
