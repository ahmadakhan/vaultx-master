# Self-hosted Keycloak and SCIM 2.0

VaultX supports a self-hosted Keycloak realm as an OIDC JWT issuer and a
standards-oriented SCIM 2.0 provisioning target. No credentials are stored in
the repository.

## OIDC

Set all three variables together:

```text
OIDC_ISSUER_URL=https://keycloak.example/realms/vaultx
OIDC_JWKS_URL=https://keycloak.example/realms/vaultx/protocol/openid-connect/certs
OIDC_AUDIENCE=vaultx
```

The verifier fetches the issuer's JWKS, restricts algorithms to RSA signing
algorithms, and requires `iss`, `aud`, `sub`, `iat`, and `exp`. Partial or
insecure (non-HTTPS outside localhost) configuration is rejected at startup;
OIDC is therefore fail-closed. `POST /auth/oidc/verify` accepts a JSON
`{"token":"..."}` payload and is intended for integration diagnostics.

## SCIM

SCIM is disabled unless both values are configured:

```text
SCIM_BEARER_TOKEN=<random value of at least 32 characters>
SCIM_TENANT_ID=customer-a
```

Keycloak's SCIM client can target `/scim/v2` and use `Authorization: Bearer`.
Implemented resources are `Users` create, read, and delete. Creation maps
`userName` (or the first email value) to `User.email`, assigns the configured
tenant, and maps an `admin` group to the existing `admin` role; all other users
receive `user`. DELETE is a deprovisioning soft-disable (`is_active=false`),
preserving auditability and tenant data. Invalid credentials return 401 and
all SCIM requests return 404 while disabled.

SCIM-generated accounts receive a random unusable local password and placeholder
client-key bundle metadata. Keycloak remains the authentication authority;
SCIM does not attempt password synchronization or PAKE/OPAQUE.

## PAKE/OPAQUE status

`PASSWORD_AUTH_MODE=opaque-required` fail-closes local password registration
and login until an approved PAKE/OPAQUE implementation is deployed. The
default `legacy-bcrypt` mode exists only for compatibility and must not be
described as zero-knowledge. OIDC/SCIM users can continue through the IdP
session path without sending a VaultX password.

`POST /auth/oidc/session` exchanges a verified token for the normal VaultX
access/refresh session response and provisions a local user when needed. The
request includes the client-generated encrypted VaultX key bundle; VaultX
never receives or changes an OIDC user's password.

SCIM `Users` supports create, list, read, patch, and delete. List supports
`startIndex`, `count`, and `userName eq "..."`; resource responses use
`application/scim+json` and include `ETag` plus `meta.version`. Deprovisioning
revokes outstanding refresh sessions and records a hash-chained audit event.
