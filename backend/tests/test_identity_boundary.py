"""Focused regression tests for the privileged authorization boundary."""

from app.core.permissions import Permission, role_allows


def test_permissions_are_granular_and_unknown_roles_fail_closed():
    assert role_allows("admin", Permission.USER_DEACTIVATE)
    assert role_allows("admin", Permission.TENANT_QUOTA_WRITE)
    assert role_allows("user", Permission.USER_READ)
    assert not role_allows("user", Permission.USER_DEACTIVATE)
    assert not role_allows("unknown", Permission.ADMIN_ACCESS)
