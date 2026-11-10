-- plpgsql_wrap--1.0--1.1.sql
--
-- Security fixes:
--   * verify_blob() was a SECURITY DEFINER plpgsql function without a
--     fixed search_path, executable by PUBLIC: a user could hijack the
--     NOT LIKE operator through search_path and run code as the extension
--     owner (a superuser).  It is replaced by the C function performing
--     the real AES-256-GCM authentication, without SECURITY DEFINER.
--   * the validator was executable by PUBLIC.  The C code now checks
--     CheckFunctionValidatorAccess(); direct calls are also revoked.

\echo Use "ALTER EXTENSION plpgsql_wrap UPDATE TO '1.1'" to load this file. \quit

CREATE OR REPLACE FUNCTION plpgsql_wrap.verify_blob(p_prosrc text)
RETURNS boolean
LANGUAGE C STRICT
AS '$libdir/plpgsql_wrap', 'pgwrap_verify_blob';

ALTER FUNCTION plpgsql_wrap.verify_blob(text) SECURITY INVOKER;

COMMENT ON FUNCTION plpgsql_wrap.verify_blob(text) IS
    'Returns false if the string is not in PLPGSQLWRAP:1: format, true if '
    'it authenticates with the compiled-in key, raises an error otherwise.';

REVOKE EXECUTE ON FUNCTION plpgsql_wrap.validator(oid) FROM PUBLIC;
