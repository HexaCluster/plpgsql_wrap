-- plpgsql_wrap--1.1.sql
--
-- Registers the plpgsql_wrap procedural language.
--
-- pg_dump / pg_restore behaviour
-- ================================
-- pg_dump produces:
--
--   CREATE OR REPLACE FUNCTION myschema.my_func(...)
--   RETURNS ...
--   LANGUAGE plpgsql_wrap
--   AS $$
--   PLPGSQLWRAP:1:5752415001...hex...
--   $$;
--
-- On pg_restore or psql execution of the dump script:
--   • The validator detects the PLPGSQLWRAP:1: prefix.
--   • It authenticates the blob with the compile-time key (GCM tag check).
--   • It accepts the blob as-is — no re-encryption, no re-validation.
--   • The function is immediately callable.
--
-- Requirements for restore:
--   • The same plpgsql_wrap.so (same compile-time key) must be installed.
--   • A different .so (different key) → authentication error on first call.
--
-- Pre-wrapped input (Oracle-style)
-- ==================================
-- A user or migration tool may supply an already-wrapped blob directly:
--
--   CREATE OR REPLACE FUNCTION myschema.my_func(...)
--   RETURNS ...
--   LANGUAGE plpgsql_wrap
--   AS $$
--   PLPGSQLWRAP:1:<hex>
--   $$;
--
-- This is accepted identically to a pg_restore operation.

\echo Use "CREATE EXTENSION plpgsql_wrap" to load this file. \quit

-- ====================================================================
-- Schema
-- ====================================================================
CREATE SCHEMA plpgsql_wrap;

COMMENT ON SCHEMA plpgsql_wrap IS
    'Helpers for the plpgsql_wrap procedural language';

-- ====================================================================
-- C-backed: call handler and validator
-- ====================================================================
CREATE FUNCTION plpgsql_wrap.call_handler()
    RETURNS language_handler
    LANGUAGE C
    AS '$libdir/plpgsql_wrap', 'pgwrap_call_handler';

CREATE FUNCTION plpgsql_wrap.validator(oid)
    RETURNS void
    LANGUAGE C STRICT
    AS '$libdir/plpgsql_wrap', 'pgwrap_validator';

-- PostgreSQL calls the validator internally, no EXECUTE privilege needed.
-- Do not let users call it directly with arbitrary OIDs.
REVOKE EXECUTE ON FUNCTION plpgsql_wrap.validator(oid) FROM PUBLIC;

-- ====================================================================
-- Register the language
-- ====================================================================
CREATE LANGUAGE plpgsql_wrap
    HANDLER   plpgsql_wrap.call_handler
    VALIDATOR plpgsql_wrap.validator;

COMMENT ON LANGUAGE plpgsql_wrap IS
    'PL/pgSQL with Oracle-WRAP-style encryption.  '
    'Source is validated then AES-256-GCM encrypted into pg_proc.prosrc.  '
    'pg_dump output is directly restorable.  '
    'Pre-wrapped blobs accepted as AS $$ body.  '
    'Key is compiled into plpgsql_wrap.so.';

-- ====================================================================
-- unwrap_procedure(key, schema, name)
-- ====================================================================
CREATE FUNCTION plpgsql_wrap.unwrap_procedure(
    p_key    text,
    p_schema    text,
    p_name      text
)
    RETURNS void
    LANGUAGE C STRICT
    AS '$libdir/plpgsql_wrap', 'pgwrap_unwrap_procedure';

COMMENT ON FUNCTION plpgsql_wrap.unwrap_procedure(text, text, text) IS
    'Superuser only.  Decrypt prosrc and switch prolang to plpgsql.  '
    'The function becomes a normal PL/pgSQL function permanently.  '
    'Requires the matching compiled .so and the corresponding key.';

REVOKE EXECUTE ON FUNCTION plpgsql_wrap.unwrap_procedure(text, text, text)
    FROM PUBLIC;

-- ====================================================================
-- unwrap_procedure(key, schema, name, args)
-- ====================================================================
CREATE FUNCTION plpgsql_wrap.unwrap_procedure(
    p_key    text,
    p_schema    text,
    p_name      text,
    p_args      text
)
    RETURNS void
    LANGUAGE C STRICT
    AS '$libdir/plpgsql_wrap', 'pgwrap_unwrap_procedure';

REVOKE EXECUTE ON FUNCTION plpgsql_wrap.unwrap_procedure(text, text, text, text)
    FROM PUBLIC;

-- ====================================================================
-- list_wrapped() — audit view, no key material exposed
-- ====================================================================
CREATE OR REPLACE FUNCTION plpgsql_wrap.list_wrapped()
RETURNS TABLE (
    schema          name,
    func_name       name,
    identity_args   text,
    return_type     text,
    wrapped_chars   int
)
LANGUAGE sql STABLE AS $$
    SELECT
        n.nspname,
        p.proname,
        pg_catalog.pg_get_function_identity_arguments(p.oid),
        pg_catalog.format_type(p.prorettype, NULL),
        length(p.prosrc)
    FROM   pg_catalog.pg_proc      p
    JOIN   pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    JOIN   pg_catalog.pg_language  l ON l.oid = p.prolang
    WHERE  l.lanname = 'plpgsql_wrap'
    ORDER  BY n.nspname, p.proname;
$$;

GRANT EXECUTE ON FUNCTION plpgsql_wrap.list_wrapped() TO PUBLIC;

COMMENT ON FUNCTION plpgsql_wrap.list_wrapped() IS
    'Lists all functions using LANGUAGE plpgsql_wrap.  '
    'Shows metadata only; no key material or plaintext source exposed.';

-- ====================================================================
-- verify_blob(prosrc text) — check a wrapped prosrc string is authentic
-- ====================================================================
-- Useful after a pg_dump / pg_restore to confirm every blob decrypts
-- correctly with the current key before going live.
--
-- Plain C function performing the full AES-256-GCM authentication.
-- Not SECURITY DEFINER: the 1.0 plpgsql version was SECURITY DEFINER
-- without a fixed search_path and could be hijacked to run arbitrary code
-- as the extension owner.
--
CREATE FUNCTION plpgsql_wrap.verify_blob(p_prosrc text)
RETURNS boolean
LANGUAGE C STRICT
AS '$libdir/plpgsql_wrap', 'pgwrap_verify_blob';

COMMENT ON FUNCTION plpgsql_wrap.verify_blob(text) IS
    'Returns false if the string is not in PLPGSQLWRAP:1: format, true if '
    'it authenticates with the compiled-in key, raises an error otherwise.';

GRANT EXECUTE ON FUNCTION plpgsql_wrap.verify_blob(text) TO PUBLIC;
