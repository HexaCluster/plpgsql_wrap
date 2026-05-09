-- sql/03_replace.sql — CREATE OR REPLACE on an already-wrapped function

-- 1. Create initial version
CREATE OR REPLACE FUNCTION public.wrap_double(n integer)
RETURNS integer
LANGUAGE plpgsql_wrap
AS $$
BEGIN
    RETURN n * 2;
END;
$$;

SELECT wrap_double(7);      -- expect 14

-- 2. Capture original wrapped prosrc
SELECT prosrc AS v1_prosrc
FROM   pg_proc WHERE proname = 'wrap_double' \gset

-- 3. Replace with new logic
CREATE OR REPLACE FUNCTION public.wrap_double(n integer)
RETURNS integer
LANGUAGE plpgsql_wrap
AS $$
BEGIN
    RETURN n * 2 + 1;      -- changed
END;
$$;

SELECT wrap_double(7);      -- expect 15

-- 4. Wrapped prosrc must have changed (new nonce each wrap)
SELECT prosrc <> :'v1_prosrc' AS prosrc_changed
FROM   pg_proc WHERE proname = 'wrap_double';
-- expect: t

-- 5. Still wrapped (not plain source)
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS still_wrapped
FROM   pg_proc WHERE proname = 'wrap_double';
-- expect: t

-- 6. Syntax error on replace also rolls back cleanly
DO $$
BEGIN
    BEGIN
        EXECUTE $dyn$
            CREATE OR REPLACE FUNCTION public.wrap_double(n integer)
            RETURNS integer LANGUAGE plpgsql_wrap AS $src$
            BEGIN INVALID SYNTAX $src$
        $dyn$;
        RAISE EXCEPTION 'should not reach here';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Caught expected error: %', SQLERRM;
    END;
END;
$$;

-- Function must still return 15 (not corrupted by failed replace)
SELECT wrap_double(7);      -- expect 15

DROP FUNCTION public.wrap_double(integer);
