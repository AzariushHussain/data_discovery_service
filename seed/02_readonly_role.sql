-- Local demo credentials only. customer_ro remains the historical bootstrap admin.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'discovery_reader') THEN
        CREATE ROLE discovery_reader LOGIN PASSWORD 'discovery_reader_password'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
    ELSIF EXISTS (
        SELECT FROM pg_roles WHERE rolname = 'discovery_reader'
        AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit OR NOT rolcanlogin)
    ) OR EXISTS (
        SELECT FROM pg_auth_members
        WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'discovery_reader')
    ) OR EXISTS (
        SELECT FROM pg_class
        WHERE relnamespace = 'public'::regnamespace
          AND relowner = (SELECT oid FROM pg_roles WHERE rolname = 'discovery_reader')
    ) OR EXISTS (
        SELECT FROM pg_database
        WHERE datname = current_database()
          AND datdba = (SELECT oid FROM pg_roles WHERE rolname = 'discovery_reader')
    ) OR EXISTS (
        SELECT FROM pg_namespace
        WHERE nspname = 'public'
          AND nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'discovery_reader')
    ) THEN
        RAISE EXCEPTION 'Existing discovery_reader has unexpected privileges, memberships, or ownership; inspect it manually.';
    END IF;
END
$$;

-- Remove PUBLIC write/create capabilities in this dedicated sample database.
REVOKE CREATE, TEMPORARY ON DATABASE ecommerce_prod FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE ecommerce_prod FROM discovery_reader;
GRANT CONNECT ON DATABASE ecommerce_prod TO discovery_reader;
REVOKE ALL ON SCHEMA public FROM discovery_reader;
GRANT USAGE ON SCHEMA public TO discovery_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM discovery_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO discovery_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM discovery_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE customer_ro IN SCHEMA public
    GRANT SELECT ON TABLES TO discovery_reader;
ALTER ROLE discovery_reader SET default_transaction_read_only = on;
