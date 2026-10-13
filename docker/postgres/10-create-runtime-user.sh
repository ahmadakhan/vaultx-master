#!/bin/sh
set -eu

# The migration role owns the schema.  The API receives a separate, least-
# privilege role; this runs only during first database initialization.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=migration_user="$POSTGRES_USER" \
  --set=runtime_user="$DB_RUNTIME_USER" \
  --set=runtime_password="$DB_RUNTIME_PASSWORD" <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_user') THEN
        EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', :'runtime_user', :'runtime_password');
    ELSE
        EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L', :'runtime_user', :'runtime_password');
    END IF;
END
$$;
GRANT CONNECT ON DATABASE vaultx TO :"runtime_user";
GRANT USAGE ON SCHEMA public TO :"runtime_user";
GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON ALL TABLES IN SCHEMA public
  TO :"runtime_user";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public
  TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_user" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE, REFERENCES ON TABLES TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_user" IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :"runtime_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_user" IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO :"runtime_user";
SQL
