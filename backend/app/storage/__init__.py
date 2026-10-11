"""Bounded, owner-scoped filesystem staging with non-overwriting publication."""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from app.core.exceptions import ConflictError, NotFoundError, ValidationError


class FileSystemStorage:
    def __init__(self, root: str | None = None) -> None:
        if root is None:
            from app.config import settings
            root = settings.storage_dir
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @staticmethod
    def _id(value: str) -> str:
        try:
            return str(uuid.UUID(value))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValidationError("Invalid storage identifier") from exc

    def _safe(self, path: Path) -> Path:
        if not path.resolve().is_relative_to(self.root):
            raise ValidationError("Invalid storage path")
        return path

    def _blob_dir(self, file_id: str) -> Path:
        file_id = self._id(file_id)
        return self._safe(self.root / "blobs" / file_id[:2] / file_id)

    def _staging_dir(self, upload_id: str) -> Path:
        return self._safe(self.root / "staging" / self._id(upload_id))

    def _final_path(self, file_id: str) -> Path:
        return self._safe(self._blob_dir(file_id) / f"{self._id(file_id)}.ciphertext")

    def validated_path(self, file_id: str, stored_path: str) -> Path:
        path = self._final_path(file_id)
        if Path(stored_path).resolve() != path.resolve() or not path.is_file():
            raise NotFoundError("File blob not found on disk")
        return path

    @contextmanager
    def upload_lock(self, upload_id: str):
        locks = self._safe(self.root / "locks")
        locks.mkdir(exist_ok=True, mode=0o700)
        # Keep lock inodes stable: unlinking permits concurrent lock holders.
        with open(self._safe(locks / self._id(upload_id)), "a+b") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ConflictError("Upload is busy; retry later") from exc
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def write_chunk(self, upload_id: str, chunk_index: int, total_chunks: int,
                    data: bytes | BinaryIO, is_last: bool, *, max_bytes: int = 11_000_000_000,
                    metadata: dict | None = None) -> bool:
        if not 1 <= total_chunks <= 10000 or not 0 <= chunk_index < total_chunks:
            raise ValidationError("Invalid chunk sequence")
        if is_last and chunk_index != total_chunks - 1:
            raise ValidationError("Invalid final chunk")
        staging = self._staging_dir(upload_id)
        staging.mkdir(parents=True, exist_ok=True, mode=0o700)
        meta_path = self._safe(staging / "meta.json")
        if meta_path.exists():
            manifest = json.loads(meta_path.read_text())
        elif chunk_index == 0:
            manifest = {"total_chunks": total_chunks, "next": 0, "size": 0,
                        "metadata": metadata or {}}
        else:
            raise ValidationError("First chunk is missing")
        if manifest["total_chunks"] != total_chunks or manifest["next"] != chunk_index:
            raise ConflictError("Chunk sequence changed or chunk already received")
        part = self._safe(staging / f"chunk_{chunk_index:010d}")
        size = manifest["size"]
        try:
            with open(part, "wb") as out:
                if isinstance(data, bytes):
                    if size + len(data) > max_bytes:
                        raise ValidationError("Upload exceeds maximum size")
                    out.write(data)
                    size += len(data)
                else:
                    while chunk := data.read(1024 * 1024):
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValidationError("Upload exceeds maximum size")
                        out.write(chunk)
            manifest.update(next=chunk_index + 1, size=size)
            tmp = staging / "meta.tmp"
            tmp.write_text(json.dumps(manifest))
            os.replace(tmp, meta_path)
        except Exception:
            part.unlink(missing_ok=True)
            raise
        if chunk_index == total_chunks - 1:
            with open(staging / "assembled", "wb") as out:
                for index in range(total_chunks):
                    with open(staging / f"chunk_{index:010d}", "rb") as inp:
                        shutil.copyfileobj(inp, out, length=1024 * 1024)
            return True
        return False

    def upload_metadata(self, upload_id: str) -> dict:
        return json.loads((self._staging_dir(upload_id) / "meta.json").read_text())["metadata"]

    def upload_size(self, upload_id: str) -> int:
        return json.loads((self._staging_dir(upload_id) / "meta.json").read_text())["size"]

    def finalize_upload(self, upload_id: str, file_id: str) -> Path:
        staging = self._staging_dir(upload_id)
        assembled = staging / "assembled"
        if not assembled.is_file():
            raise ValidationError("Upload not complete; cannot finalize")
        dest = self._final_path(file_id)
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.link(assembled, dest)
        except FileExistsError as exc:
            raise ConflictError("File blob already exists") from exc
        shutil.rmtree(staging)
        return dest

    def cancel_upload(self, upload_id: str) -> None:
        shutil.rmtree(self._staging_dir(upload_id), ignore_errors=True)

    def read_stream(self, file_id: str, offset: int = 0, length: int | None = None) -> BinaryIO:
        if offset < 0 or (length is not None and length < 0):
            raise ValidationError("Invalid byte range")
        path = self._final_path(file_id)
        if not path.is_file():
            raise NotFoundError("File blob not found on disk")
        stream = open(path, "rb")  # noqa: SIM115 - caller owns the returned stream
        stream.seek(offset)
        return stream

    def file_size(self, file_id: str) -> int:
        path = self._final_path(file_id)
        return path.stat().st_size if path.is_file() else 0

    def delete_blob(self, file_id: str) -> None:
        self._final_path(file_id).unlink(missing_ok=True)


_storage: FileSystemStorage | None = None


def get_storage() -> FileSystemStorage:
    global _storage
    if _storage is None:
        _storage = FileSystemStorage()
    return _storage
