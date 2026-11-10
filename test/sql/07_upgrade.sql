-- 07_upgrade.sql
--
-- Upgrade path 1.0 -> 1.1 (run last: drops and recreates the extension).
SET client_min_messages = warning;
DROP EXTENSION IF EXISTS plpgsql_wrap CASCADE;
CREATE EXTENSION plpgsql_wrap VERSION '1.0';
RESET client_min_messages;

CREATE VIEW regress_pwrap_state AS
SELECT (SELECT extversion FROM pg_extension
         WHERE extname = 'plpgsql_wrap')                     AS version,
       (SELECT l.lanname
          FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
         WHERE p.oid = to_regprocedure('plpgsql_wrap.verify_blob(text)'))
                                                             AS verify_lang,
       (SELECT prosecdef FROM pg_proc
         WHERE oid = to_regprocedure('plpgsql_wrap.verify_blob(text)'))
                                                             AS verify_secdef,
       (SELECT EXISTS (
           SELECT 1
             FROM pg_proc p,
                  aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
            WHERE p.oid = to_regprocedure('plpgsql_wrap.validator(oid)')
              AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
                                                             AS validator_public;

SELECT * FROM regress_pwrap_state;

ALTER EXTENSION plpgsql_wrap UPDATE TO '1.1';
SELECT * FROM regress_pwrap_state;

-- a fresh 1.1 install gives the same result
SET client_min_messages = warning;
DROP EXTENSION plpgsql_wrap CASCADE;
CREATE EXTENSION plpgsql_wrap;
RESET client_min_messages;
SELECT * FROM regress_pwrap_state;

-- wrapped functions work after the upgrade
CREATE FUNCTION regress_pwrap_up(i int) RETURNS int LANGUAGE plpgsql_wrap
    AS $$ BEGIN RETURN i + 1000; END $$;
SELECT regress_pwrap_up(1);
SELECT plpgsql_wrap.verify_blob(prosrc) FROM pg_proc WHERE proname = 'regress_pwrap_up';

DROP FUNCTION regress_pwrap_up(int);
DROP VIEW regress_pwrap_state;
