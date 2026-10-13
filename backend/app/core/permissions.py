"""Small, explicit permission vocabulary used by API dependencies.

Roles remain backwards compatible (``admin`` and ``user``), while endpoint
code can ask for a capability instead of scattering role-name checks.  This is
an authorization boundary, not a claim that the database is a policy engine.
Organizations can replace the map with persisted grants in a later migration.
"""

from __future__ import annotations

from enum import StrEnum


class Permission(StrEnum):
    ADMIN_ACCESS = "admin.access"
    USER_READ = "user.read"
    AUDIT_READ = "audit.read"
    TENANT_QUOTA_READ = "tenant.quota.read"
    TENANT_QUOTA_WRITE = "tenant.quota.write"
    USER_DEACTIVATE = "user.deactivate"


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "user": frozenset({Permission.USER_READ}),
    "admin": frozenset(Permission),
}


def role_allows(role: str, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
