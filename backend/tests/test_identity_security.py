"""Identity regressions run in a subprocess with synthetic config and fresh DBs.

No project dotenv, existing database, signing keys, or storage are read. The
subprocess boundary prevents module-level settings from contaminating other suites.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

if os.environ.get("VAULTX_IDENTITY_TEST_CHILD") != "1":

    def test_identity_security_isolated():
        env = os.environ.copy()
        env["VAULTX_IDENTITY_TEST_CHILD"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(Path(__file__).resolve()), "-q"],
            env=env,
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert result.returncode == 0, result.stdout + result.stderr
else:
    import base64
    import json
    import uuid
    from datetime import UTC, datetime, timedelta
    from types import SimpleNamespace
    from unittest.mock import patch

    import httpx
    import jwt
    import pyotp
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pydantic_settings.sources import DotEnvSettingsSource
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    @pytest.fixture(scope="session")
    def modules(tmp_path_factory):
        root = tmp_path_factory.mktemp("identity-synthetic")
        env = {
            "APP_ENV": "test",
            "APP_SECRET_KEY": "synthetic-app-secret-" + "a" * 32,
            "JWT_SECRET_KEY": "synthetic-jwt-secret-" + "b" * 32,
            "DB_HOST": "unused.invalid",
            "DB_NAME": "synthetic",
            "DB_USER": "synthetic",
            "DB_PASSWORD": "synthetic",
            "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "MAIL_HOST": "unused.invalid",
            "MAIL_USERNAME": "synthetic",
            "MAIL_PASSWORD": "synthetic",
            "MAIL_FROM": "test@example.com",
            "KEYS_DIR": str(root / "keys"),
            "FALLBACK_KEYS_DIR": str(root / "fallback"),
            "STORAGE_DIR": str(root / "storage"),
            "LOGIN_MAX_ATTEMPTS": "5",
            "LOGIN_LOCKOUT_SECONDS": "900",
        }
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(DotEnvSettingsSource, "_read_env_files", return_value={}),
        ):
            from app.api.routers import admin, auth
            from app.config import Settings, settings
            from app.core import deps, security
            from app.db import get_db
            from app.main import _register_exception_handlers
            from app.models import Base, RefreshToken, Role, TamperLog, User, UserRole

            yield SimpleNamespace(
                admin=admin,
                auth=auth,
                Settings=Settings,
                settings=settings,
                deps=deps,
                security=security,
                get_db=get_db,
                _register_exception_handlers=_register_exception_handlers,
                Base=Base,
                RefreshToken=RefreshToken,
                Role=Role,
                TamperLog=TamperLog,
                User=User,
                UserRole=UserRole,
                env=env,
            )

    @pytest.fixture
    async def rig(modules):
        from fastapi import FastAPI

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(modules.Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        async with sessions() as db:
            db.add_all([modules.Role(name="user"), modules.Role(name="admin")])
            await db.commit()
        app = FastAPI()
        modules._register_exception_handlers(app)
        app.include_router(modules.auth.router)
        app.include_router(modules.admin.router)

        async def get_db():
            async with sessions() as db:
                yield db

        app.dependency_overrides[modules.get_db] = get_db
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield SimpleNamespace(client=client, sessions=sessions, m=modules, app=app)
        await engine.dispose()

    @pytest.fixture(scope="session")
    def bundle():
        public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

        def encode(data):
            return base64.b64encode(data).decode()

        return {
            "email": "user@example.com",
            "password": "SyntheticPass123!",
            "password_salt_b64": encode(b"s" * 16),
            "enc_master_key_b64": encode(b"m" * 48),
            "enc_master_key_iv": encode(b"i" * 12),
            "enc_search_key_b64": encode(b"s" * 48),
            "enc_search_key_iv": encode(b"j" * 12),
            "enc_private_key_b64": encode(b"p" * 128),
            "enc_private_key_iv": encode(b"k" * 12),
            "public_key_b64": encode(
                public.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ),
            "kdf_iterations": 600000,
            "key_bundle_version": 2,
        }

    async def register(rig, bundle):
        response = await rig.client.post("/auth/register", json=bundle)
        assert response.status_code == 200, response.text
        return response.json()

    def bearer(tokens):
        return {"Authorization": "Bearer " + tokens["access_token"]}

    async def enroll(rig, bundle):
        tokens = await register(rig, bundle)
        response = await rig.client.post("/auth/mfa/setup", headers=bearer(tokens))
        assert response.status_code == 200, response.text
        setup = response.json()
        setup["enabled_code"] = pyotp.TOTP(setup["secret"]).now()
        response = await rig.client.post(
            "/auth/mfa/enable", headers=bearer(tokens), json={"code": setup["enabled_code"]}
        )
        assert response.status_code == 200, response.text
        return tokens, setup

    @pytest.mark.asyncio
    async def test_registration_never_bootstraps_admin(rig, bundle):
        tokens = await register(rig, bundle)
        async with rig.sessions() as db:
            assert (await db.scalars(select(rig.m.UserRole.role))).all() == ["user"]
        response = await rig.client.get("/admin/users", headers=bearer(tokens))
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_legacy_bundle_metadata_and_ciphertext_preserved(rig, bundle):
        legacy = {
            key: value
            for key, value in bundle.items()
            if key not in ("kdf_iterations", "key_bundle_version")
        }
        tokens = await register(rig, legacy)
        assert tokens["keys"]["kdf_iterations"] == 150000
        assert tokens["keys"]["key_bundle_version"] == 1
        assert tokens["keys"]["enc_master_key_b64"] == bundle["enc_master_key_b64"]
        response = await rig.client.post(
            "/auth/login", json={"email": bundle["email"], "password": bundle["password"]}
        )
        assert response.status_code == 200
        assert response.json()["keys"] == tokens["keys"]

    @pytest.mark.asyncio
    async def test_logout_revokes_access_and_refresh(rig, bundle):
        tokens = await register(rig, bundle)
        assert (await rig.client.get("/auth/mfa/status", headers=bearer(tokens))).status_code == 200
        response = await rig.client.post(
            "/auth/logout", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 200
        assert (await rig.client.get("/auth/mfa/status", headers=bearer(tokens))).status_code == 401
        assert (
            await rig.client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        ).status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_rotation_replay_persists_revocation(rig, bundle):
        tokens = await register(rig, bundle)
        response = await rig.client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 200, response.text
        rotated = response.json()
        assert (
            await rig.client.get("/auth/mfa/status", headers=bearer(rotated))
        ).status_code == 200
        replay = await rig.client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert replay.status_code == 401
        assert (
            await rig.client.get("/auth/mfa/status", headers=bearer(rotated))
        ).status_code == 401
        async with rig.sessions() as db:
            rows = (await db.scalars(select(rig.m.RefreshToken))).all()
            assert all(row.revoked_at is not None for row in rows)

    @pytest.mark.asyncio
    async def test_mfa_enrollment_binary_round_trip_and_session_revocation(rig, bundle):
        old, setup = await enroll(rig, bundle)
        assert len(setup["backup_codes"]) == 10
        assert (await rig.client.get("/auth/mfa/status", headers=bearer(old))).status_code == 401
        assert (
            await rig.client.post("/auth/refresh", json={"refresh_token": old["refresh_token"]})
        ).status_code == 401

    @pytest.mark.asyncio
    async def test_challenge_gates_keys_and_is_single_use(rig, bundle):
        _, setup = await enroll(rig, bundle)
        response = await rig.client.post(
            "/auth/login", json={"email": bundle["email"], "password": bundle["password"]}
        )
        challenge = response.json()
        assert response.status_code == 200 and challenge["mfa_required"]
        assert challenge["keys"] is None and challenge["refresh_token"] == ""
        assert (
            await rig.client.get("/auth/mfa/status", headers=bearer(challenge))
        ).status_code == 401
        response = await rig.client.post(
            "/auth/mfa/verify", headers=bearer(challenge), json={"code": setup["backup_codes"][0]}
        )
        assert response.status_code == 200, response.text
        full = response.json()
        assert full["keys"] is not None
        claims = rig.m.security.decode_token(full["access_token"])
        assert rig.m.deps.valid_mfa_claim(claims, recent=True)
        response = await rig.client.post(
            "/auth/mfa/verify", headers=bearer(challenge), json={"code": setup["backup_codes"][1]}
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_inline_backup_login_preserves_assurance_on_refresh(rig, bundle):
        _, setup = await enroll(rig, bundle)
        response = await rig.client.post(
            "/auth/login",
            json={
                "email": bundle["email"],
                "password": bundle["password"],
                "code": setup["backup_codes"][0],
            },
        )
        assert response.status_code == 200, response.text
        full = response.json()
        before = rig.m.security.decode_token(full["access_token"])
        response = await rig.client.post(
            "/auth/refresh", json={"refresh_token": full["refresh_token"]}
        )
        assert response.status_code == 200, response.text
        after = rig.m.security.decode_token(response.json()["access_token"])
        assert after["mfa_at"] == before["mfa_at"]
        response = await rig.client.post("/auth/mfa/setup", headers=bearer(response.json()))
        assert response.status_code == 409
        replay = await rig.client.post(
            "/auth/login",
            json={
                "email": bundle["email"],
                "password": bundle["password"],
                "code": setup["backup_codes"][0],
            },
        )
        assert replay.status_code == 401

    @pytest.mark.asyncio
    async def test_totp_cannot_be_reused_after_enrollment(rig, bundle):
        _, setup = await enroll(rig, bundle)
        response = await rig.client.post(
            "/auth/login",
            json={
                "email": bundle["email"],
                "password": bundle["password"],
                "code": setup["enabled_code"],
            },
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_mfa_disable_revokes_all_sessions(rig, bundle):
        _, setup = await enroll(rig, bundle)
        response = await rig.client.post(
            "/auth/login",
            json={
                "email": bundle["email"],
                "password": bundle["password"],
                "code": setup["backup_codes"][0],
            },
        )
        assert response.status_code == 200
        tokens = response.json()
        response = await rig.client.post(
            "/auth/mfa/disable",
            headers=bearer(tokens),
            json={"code": setup["backup_codes"][1], "use_backup": True},
        )
        assert response.status_code == 200, response.text
        assert (await rig.client.get("/auth/mfa/status", headers=bearer(tokens))).status_code == 401
        response = await rig.client.post(
            "/auth/login", json={"email": bundle["email"], "password": bundle["password"]}
        )
        assert response.status_code == 200 and not response.json()["mfa_required"]

    @pytest.mark.asyncio
    async def test_password_only_session_cannot_bypass_enabled_mfa(rig, bundle):
        _, _ = await enroll(rig, bundle)
        async with rig.sessions() as db:
            user = await db.scalar(select(rig.m.User))
            access, refresh = await rig.m.auth._issue_tokens(db, user)
        assert (
            await rig.client.get("/auth/mfa/status", headers={"Authorization": "Bearer " + access})
        ).status_code == 401
        assert (
            await rig.client.post("/auth/refresh", json={"refresh_token": refresh})
        ).status_code == 401

    @pytest.mark.asyncio
    async def test_shared_budget_expires(rig):
        from app.core.auth_budget import reserve_attempt
        from app.core.exceptions import RateLimitError
        from app.models.user import AuthenticationAttempt

        async with rig.sessions() as first:
            for _ in range(5):
                await reserve_attempt(first, "test", "synthetic")
        async with rig.sessions() as second:
            with pytest.raises(RateLimitError):
                await reserve_attempt(second, "test", "synthetic")
            row = await second.scalar(select(AuthenticationAttempt))
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            await second.commit()
        async with rig.sessions() as third:
            await reserve_attempt(third, "test", "synthetic")
            assert (await third.scalar(select(AuthenticationAttempt))).attempts == 1

    @pytest.mark.asyncio
    async def test_mfa_budget_not_reset_by_correct_password(rig, bundle):
        _, setup = await enroll(rig, bundle)
        # Enrollment consumed one attempt; failures from separate sessions share
        # the remaining four attempts. A correct password does not replenish it.
        for _ in range(4):
            response = await rig.client.post(
                "/auth/login",
                json={"email": bundle["email"], "password": bundle["password"], "code": "f" * 20},
            )
            assert response.status_code == 401
        response = await rig.client.post(
            "/auth/login",
            json={
                "email": bundle["email"],
                "password": bundle["password"],
                "code": setup["backup_codes"][0],
            },
        )
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0

    @pytest.mark.asyncio
    async def test_password_budget_shared_across_sessions(rig, bundle):
        await register(rig, bundle)
        for _ in range(5):
            response = await rig.client.post(
                "/auth/login", json={"email": bundle["email"], "password": "wrong"}
            )
            assert response.status_code == 401
        response = await rig.client.post(
            "/auth/login", json={"email": bundle["email"], "password": bundle["password"]}
        )
        assert response.status_code == 429

    @pytest.mark.asyncio
    async def test_admin_cannot_self_deactivate_or_create_empty_vault(rig, bundle):
        tokens = await register(rig, bundle)
        uid = uuid.UUID(rig.m.security.decode_token(tokens["access_token"])["sub"])
        async with rig.sessions() as db:
            db.add(rig.m.UserRole(user_id=uid, role="admin"))
            await db.commit()
        response = await rig.client.delete(f"/admin/users/{uid}", headers=bearer(tokens))
        assert response.status_code == 403
        response = await rig.client.post(
            "/admin/users",
            headers=bearer(tokens),
            json={"email": "other@example.com", "password": "SyntheticPass123!"},
        )
        assert response.status_code == 409
        async with rig.sessions() as db:
            assert len((await db.scalars(select(rig.m.User))).all()) == 1

    @pytest.mark.asyncio
    async def test_audit_never_records_refresh_secret(rig, bundle):
        tokens = await register(rig, bundle)
        response = await rig.client.post(
            "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        )
        assert response.status_code == 200
        async with rig.sessions() as db:
            logs = (await db.scalars(select(rig.m.TamperLog))).all()
            assert any(log.entry_json["action"] == "token_refresh" for log in logs)
            text = json.dumps([log.entry_json for log in logs])
            assert tokens["refresh_token"] not in text
            assert response.json()["refresh_token"] not in text

    @pytest.mark.asyncio
    async def test_admin_deactivation_revokes_target_sessions_and_audits(rig, bundle):
        admin = await register(rig, bundle)
        target = await register(rig, {**bundle, "email": "target@example.com"})
        admin_id = uuid.UUID(rig.m.security.decode_token(admin["access_token"])["sub"])
        target_id = uuid.UUID(rig.m.security.decode_token(target["access_token"])["sub"])
        async with rig.sessions() as db:
            db.add(rig.m.UserRole(user_id=admin_id, role="admin"))
            await db.commit()
        response = await rig.client.delete(f"/admin/users/{target_id}", headers=bearer(admin))
        assert response.status_code == 200, response.text
        assert (await rig.client.get("/auth/mfa/status", headers=bearer(target))).status_code == 401
        async with rig.sessions() as db:
            row = await db.scalar(
                select(rig.m.RefreshToken).where(rig.m.RefreshToken.user_id == target_id)
            )
            assert row.revoked_at is not None
            logs = (
                await db.scalars(select(rig.m.TamperLog).where(rig.m.TamperLog.user_id == admin_id))
            ).all()
            assert any(log.entry_json["action"] == "user_deactivated" for log in logs)

    @pytest.mark.asyncio
    async def test_validation_rejects_malformed_bundle_without_echoing_password(rig, bundle):
        bad = {**bundle, "password": "sensitive-password", "enc_master_key_iv": "%%%"}
        response = await rig.client.post("/auth/register", json=bad)
        assert response.status_code == 422
        assert "sensitive-password" not in response.text and "input" not in response.text
        response = await rig.client.post(
            "/auth/register", json={**bundle, "key_bundle_version": None}
        )
        assert response.status_code == 422

    def test_signed_tokens_require_typed_claims(modules):
        claims = {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "jti": [],
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        }
        token = jwt.encode(claims, modules.settings.jwt_secret_key, algorithm="HS256")
        with pytest.raises(ValueError):
            modules.security.decode_token(token)
        assert not modules.deps.valid_mfa_claim({"mfa_at": True})
        assert not modules.deps.valid_mfa_claim(
            {"mfa_at": datetime.now(UTC).timestamp() - 1801}, recent=True
        )

    def test_bcrypt_long_password_is_not_truncated(modules):
        hashed = modules.security.hash_password("a" * 72)
        assert not modules.security.verify_password("a" * 72 + "suffix", hashed)

    def test_signing_key_initialization_is_shared_across_workers(modules, tmp_path, monkeypatch):
        from concurrent.futures import ThreadPoolExecutor

        from app.core.server_keys import load_server_keys

        monkeypatch.setattr(modules.settings, "keys_dir", str(tmp_path / "new-signing-keys"))
        monkeypatch.setattr(
            modules.settings, "fallback_keys_dir", str(tmp_path / "unused-fallback")
        )
        with ThreadPoolExecutor(max_workers=4) as pool:
            pairs = list(pool.map(lambda _: load_server_keys(), range(4)))
        assert len({pair[1].public_numbers().n for pair in pairs}) == 1
        assert not (tmp_path / "unused-fallback").exists()

    def test_config_escapes_credentials_and_repr(modules):
        value = modules.Settings(
            _env_file=None,
            **{**modules.env, "DATABASE_URL": None, "DB_PASSWORD": "sensitive:p@ss/word"},
        )
        assert "sensitive:p@ss/word" not in repr(value)
        assert "sensitive%3Ap%40ss%2Fword" in value.database_url
