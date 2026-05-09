-- sql/02_unwrap.sql — unwrap converts back to plain plpgsql

-- 1. Create wrapped
CREATE OR REPLACE FUNCTION public.wrap_greet(who text)
RETURNS text
LANGUAGE plpgsql_wrap
AS $$
BEGIN
    RETURN 'Hello, ' || who || '!';
END;
$$;

SELECT wrap_greet('world');     -- expect: Hello, world!

-- 2. Confirm wrapped
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS is_wrapped
FROM   pg_proc WHERE proname = 'wrap_greet';
-- expect: t

-- 3. Unwrap (superuser only)
SELECT plpgsql_wrap.unwrap_procedure(
	'0000000000000000000000000000000000000000000000000000000000000000',
	'public', 'wrap_greet');

-- 4. prosrc is now plain PL/pgSQL source
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS still_wrapped
FROM   pg_proc WHERE proname = 'wrap_greet';
-- expect: f

-- 5. language is now plpgsql, not plpgsql_wrap
SELECT l.lanname
FROM   pg_proc p
JOIN   pg_language l ON l.oid = p.prolang
WHERE  p.proname = 'wrap_greet';
-- expect: plpgsql

-- 6. Function still works as normal plpgsql
SELECT wrap_greet('PostgreSQL');    -- expect: Hello, PostgreSQL!

-- 7. No longer in list_wrapped()
SELECT count(*) FROM plpgsql_wrap.list_wrapped()
WHERE  func_name = 'wrap_greet';
-- expect: 0

DROP FUNCTION public.wrap_greet(text);

-- 8. Create wrapped
CREATE OR REPLACE FUNCTION public.wrap_greet(who text)
RETURNS text
LANGUAGE plpgsql_wrap
AS $$
BEGIN
    RETURN 'Hello, ' || who || '!';
END;
$$;

SELECT wrap_greet('world');     -- expect: Hello, world!

-- 9. Confirm wrapped
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS is_wrapped
FROM   pg_proc WHERE proname = 'wrap_greet';
-- expect: t

-- 10. Unwrap with function args (superuser only)
SELECT plpgsql_wrap.unwrap_procedure(
	'0000000000000000000000000000000000000000000000000000000000000000',
	'public', 'wrap_greet', 'who text');

-- 11. prosrc is now plain PL/pgSQL source
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS still_wrapped
FROM   pg_proc WHERE proname = 'wrap_greet';
-- expect: f

-- 12. language is now plpgsql, not plpgsql_wrap
SELECT l.lanname
FROM   pg_proc p
JOIN   pg_language l ON l.oid = p.prolang
WHERE  p.proname = 'wrap_greet';
-- expect: plpgsql

-- 13. Function still works as normal plpgsql
SELECT wrap_greet('PostgreSQL');    -- expect: Hello, PostgreSQL!

-- 14. No longer in list_wrapped()
SELECT count(*) FROM plpgsql_wrap.list_wrapped()
WHERE  func_name = 'wrap_greet';
-- expect: 0

DROP FUNCTION public.wrap_greet(text);
