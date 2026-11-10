-- 06_security.sql
--
-- Regression tests for the security fixes of version 1.1.
SET client_min_messages = warning;
CREATE EXTENSION IF NOT EXISTS plpgsql_wrap;
RESET client_min_messages;
\set VERBOSITY terse

CREATE ROLE regress_pwrap_user;
CREATE SCHEMA regress_pwrap AUTHORIZATION regress_pwrap_user;
GRANT USAGE ON SCHEMA plpgsql_wrap TO regress_pwrap_user;
CREATE TABLE public.regress_pwrap_log (who name);
GRANT INSERT ON public.regress_pwrap_log TO PUBLIC;

-- ====================================================================
-- 1. Validator: no direct call on functions of other languages
-- ====================================================================
SELECT has_function_privilege('regress_pwrap_user',
                              'plpgsql_wrap.validator(oid)', 'EXECUTE');

SET ROLE regress_pwrap_user;
CREATE FUNCTION regress_pwrap.plf(x int) RETURNS int LANGUAGE plpgsql
    AS $$ BEGIN RETURN x + 1; END $$;
CREATE FUNCTION regress_pwrap.sqlf() RETURNS int LANGUAGE sql AS 'SELECT 42';
-- not executable by an ordinary user
SELECT plpgsql_wrap.validator('regress_pwrap.plf(int)'::regprocedure);
RESET ROLE;

-- even for a superuser, the C code refuses non plpgsql_wrap functions
DO $$
BEGIN
    PERFORM plpgsql_wrap.validator('regress_pwrap.plf(int)'::regprocedure);
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'plpgsql function refused (%)', SQLSTATE;
END $$;
SET check_function_bodies = off;
DO $$
BEGIN
    PERFORM plpgsql_wrap.validator('regress_pwrap.sqlf()'::regprocedure);
EXCEPTION WHEN insufficient_privilege THEN
    RAISE NOTICE 'sql function refused (%)', SQLSTATE;
END $$;
RESET check_function_bodies;

-- both functions are intact
SELECT p.proname, l.lanname, p.prosrc
  FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
 WHERE p.pronamespace = 'regress_pwrap'::regnamespace
 ORDER BY p.proname;
SELECT regress_pwrap.plf(1), regress_pwrap.sqlf();

-- a plpgsql_wrap function can still be validated
CREATE FUNCTION regress_pwrap.wf(x int) RETURNS int LANGUAGE plpgsql_wrap
    AS $$ BEGIN RETURN x * 3; END $$;
SELECT plpgsql_wrap.validator('regress_pwrap.wf(int)'::regprocedure);
SELECT regress_pwrap.wf(2);

-- ====================================================================
-- 2. verify_blob: real GCM check, not SECURITY DEFINER
-- ====================================================================
SELECT l.lanname, p.prosecdef
  FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
 WHERE p.oid = 'plpgsql_wrap.verify_blob(text)'::regprocedure;

SELECT prosrc AS blob FROM pg_proc
 WHERE oid = 'regress_pwrap.wf(int)'::regprocedure \gset
SELECT plpgsql_wrap.verify_blob(:'blob');
SELECT plpgsql_wrap.verify_blob('not a wrapped body');
-- flip one ciphertext nibble: authentication must fail
SELECT plpgsql_wrap.verify_blob(
         overlay(:'blob' PLACING
                 CASE WHEN substr(:'blob', 100, 1) = '0' THEN '1' ELSE '0' END
                 FROM 100 FOR 1));

-- search_path hijack attempt by an unprivileged user
SET ROLE regress_pwrap_user;
CREATE FUNCTION regress_pwrap.evil(text, text) RETURNS bool LANGUAGE sql AS
    $$ INSERT INTO public.regress_pwrap_log VALUES (current_user); SELECT true $$;
CREATE OPERATOR regress_pwrap.!~~ (leftarg = text, rightarg = text,
                                   function = regress_pwrap.evil);
CREATE OPERATOR regress_pwrap.~~  (leftarg = text, rightarg = text,
                                   function = regress_pwrap.evil);
SET search_path = regress_pwrap, pg_catalog;
SELECT plpgsql_wrap.verify_blob('x');
RESET search_path;
RESET ROLE;
SELECT count(*) AS hijacked FROM public.regress_pwrap_log;

-- ====================================================================
-- 3. unwrap_procedure
-- ====================================================================
GRANT EXECUTE ON FUNCTION plpgsql_wrap.unwrap_procedure(text, text, text)
    TO regress_pwrap_user;
SET ROLE regress_pwrap_user;
-- privilege is checked before the key, right or wrong
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 64), 'regress_pwrap', 'wf');
SELECT plpgsql_wrap.unwrap_procedure('bad', 'regress_pwrap', 'wf');
RESET ROLE;

SELECT plpgsql_wrap.unwrap_procedure('bad', 'regress_pwrap', 'wf');
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 63) || 'g', 'regress_pwrap', 'wf');
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 66), 'regress_pwrap', 'wf');

-- overloaded wrapped functions: ambiguity is detected
CREATE FUNCTION regress_pwrap.ovl(a int) RETURNS int LANGUAGE plpgsql_wrap
    AS $$ BEGIN RETURN 1; END $$;
CREATE FUNCTION regress_pwrap.ovl(a text) RETURNS int LANGUAGE plpgsql_wrap
    AS $$ BEGIN RETURN 2; END $$;
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 64), 'regress_pwrap', 'ovl');
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 64), 'regress_pwrap', 'ovl', 'a text');
SELECT p.oid::regprocedure, l.lanname
  FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
 WHERE p.proname = 'ovl' ORDER BY 1::text;
-- only one wrapped overload left: no longer ambiguous
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 64), 'regress_pwrap', 'ovl');
SELECT regress_pwrap.ovl(1), regress_pwrap.ovl('x');

-- functions of other languages are never candidates
SELECT plpgsql_wrap.unwrap_procedure(repeat('0', 64), 'regress_pwrap', 'plf');

-- ====================================================================
-- 4. Strict hex decoding of wrapped bodies
-- ====================================================================
CREATE FUNCTION regress_pwrap.badhex() RETURNS int LANGUAGE plpgsql_wrap
    AS $$PLPGSQLWRAP:1:+1$$;
CREATE FUNCTION regress_pwrap.badhex() RETURNS int LANGUAGE plpgsql_wrap
    AS $$PLPGSQLWRAP:1: 1$$;

-- ====================================================================
-- Cleanup
-- ====================================================================
DROP SCHEMA regress_pwrap CASCADE;
DROP TABLE public.regress_pwrap_log;
REVOKE USAGE ON SCHEMA plpgsql_wrap FROM regress_pwrap_user;
REVOKE EXECUTE ON FUNCTION plpgsql_wrap.unwrap_procedure(text, text, text)
    FROM regress_pwrap_user;
DROP ROLE regress_pwrap_user;
