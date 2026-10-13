# VaultX operations runbook

This runbook documents operational evidence for the current prototype. It does
not imply a managed backup service, a tested recovery objective, or a security
certification. An operator must complete and record each check for the actual
deployment.

## Release gates

The `Production evidence` workflow must pass on the release commit. It runs
backend tests/lint, frontend type/lint/build/security tests, and native adapter
toolchain checks. A missing toolchain or failed check is a failure; it is not
reported as a successful mobile build.

Before deployment, verify:

```sh
docker compose config
docker compose build --pull
```

Do not deploy if either command fails or if required secret variables are not
provided. Keep the generated Compose configuration and CI run URL with the
release record.

## Startup and health

```sh
docker compose up -d db
docker compose run --rm migrate
docker compose up -d backend frontend
curl --fail http://localhost:8000/health
```

Review backend and migration logs before making the service available. Signing
keys, database data, file storage, and audit logs are named volumes in Compose;
their persistence is necessary but is not a backup.

## Incident response

1. Record the UTC time, release identifier, affected volumes, and operator.
2. Preserve application and audit logs before restarting services.
3. If integrity is in doubt, stop writes and copy the database/storage volumes
   to quarantined evidence storage.
4. Rotate application credentials only after preserving the evidence needed to
   understand the incident.
5. Restore only into an isolated project first, run the verification steps in
   `BACKUP_DISASTER_RECOVERY.md`, and record the result.
