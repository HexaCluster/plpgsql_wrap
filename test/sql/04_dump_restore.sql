-- sql/04_dump_restore.sql
--
-- Tests the pg_dump / pg_restore path and pre-wrapped input.
--
-- What we simulate here:
--   A. Capture the wrapped prosrc (as pg_dump would see it).
--   B. DROP the function.
--   C. Recreate it using the captured wrapped prosrc as the AS $$ body.
--      This is exactly what pg_dump output does when pg_restore runs it.
--   D. Verify the function works correctly.
--   E. Verify a tampered blob is rejected.
--   F. Verify a blob from a plain-text SQL dump restores correctly.

-- ====================================================================
-- A. Create a function and capture its wrapped prosrc
-- ====================================================================
CREATE OR REPLACE FUNCTION public.wrap_cube(n integer)
RETURNS integer
LANGUAGE plpgsql_wrap
AS $$
BEGIN
    RETURN n * n * n;
END;
$$;

SELECT wrap_cube(3);    -- expect 27

-- Capture the wrapped prosrc (this is what pg_dump produces in the AS body)
SELECT prosrc AS wrapped_prosrc
FROM   pg_catalog.pg_proc
WHERE  proname = 'wrap_cube' \gset

-- Confirm it looks like a wrapped blob
SELECT :'wrapped_prosrc' LIKE 'PLPGSQLWRAP:1:%' AS is_wrapped_format;
-- expect: t

-- ====================================================================
-- B. Drop the function (simulate a fresh restore target)
-- ====================================================================
DROP FUNCTION public.wrap_cube(integer);

SELECT count(*) FROM pg_proc WHERE proname = 'wrap_cube';
-- expect: 0

-- ====================================================================
-- C. Restore from pg_dump output
--    This is what pg_restore / psql executes from the dump file.
--    The AS body is the raw wrapped prosrc captured above.
-- ====================================================================

-- In a real pg_dump file this looks like:
--   CREATE OR REPLACE FUNCTION public.wrap_cube(n integer)
--   RETURNS integer LANGUAGE plpgsql_wrap AS $$PLPGSQLWRAP:1:5752...$$;
--
-- We simulate this exactly using the prosrc captured above as the AS body.
-- psql's \gset stored it in :'wrapped_prosrc'; we pass it via dynamic SQL.

DO $outer$
DECLARE
    v_prosrc text;
BEGIN
    SELECT prosrc INTO v_prosrc
    FROM   pg_catalog.pg_proc
    WHERE  proname = 'wrap_cube'
    LIMIT 1;

    -- This should find 0 rows because we DROPped above — so we use
    -- the variable captured before the DROP via \gset.
    -- In the regression framework we must use a fixed known blob.
    -- See explanation below.
END;
$outer$;

-- Regression note:
-- \gset stores the variable in the psql client session.
-- We use it directly in the CREATE statement below.
-- This is exactly the SQL that pg_restore would run from a dump file:
CREATE OR REPLACE FUNCTION public.wrap_cube(n integer)
RETURNS integer
LANGUAGE plpgsql_wrap
AS :'wrapped_prosrc';
-- ↑ psql substitutes the variable here.
-- The validator receives the PLPGSQLWRAP:1: blob as the AS $$ body,
-- detects the prefix, authenticates with the compile-time key, and
-- stores it unchanged.  No re-encryption.  No plain source exposure.

-- ====================================================================
-- D. Function works after restore
-- ====================================================================
SELECT wrap_cube(4);    -- expect 64

-- prosrc is still the wrapped blob (not re-encrypted, same blob as before)
SELECT prosrc LIKE 'PLPGSQLWRAP:1:%' AS still_wrapped
FROM   pg_proc WHERE proname = 'wrap_cube';
-- expect: t

-- ====================================================================
-- E. Tampered blob is rejected at call time
-- ====================================================================
DO $$
BEGIN
    BEGIN
        -- Create a function with a blob that has correct prefix but
        -- corrupted payload (last hex chars changed)
        EXECUTE $dyn$
            CREATE OR REPLACE FUNCTION public.wrap_tampered()
            RETURNS void
            LANGUAGE plpgsql_wrap
            AS $$PLPGSQLWRAP:1:5752415001aabbccddeeff00112233445566778899aabbccddeeff0000000000$$
        $dyn$;
        -- Validator accepts it (authentication only happens on call)
        -- Now call it:
        PERFORM wrap_tampered();
        RAISE EXCEPTION 'should not reach here';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Tampered blob correctly rejected: %', SQLERRM;
    END;
END;
$$;

DROP FUNCTION IF EXISTS public.wrap_tampered();

-- ====================================================================
-- F. verify_blob() utility
-- ====================================================================
SELECT plpgsql_wrap.verify_blob(prosrc) AS blob_ok
FROM   pg_proc WHERE proname = 'wrap_cube';
-- expect: t

SELECT plpgsql_wrap.verify_blob('BEGIN RETURN 1; END;') AS plain_not_blob;
-- expect: f

-- Cleanup
DROP FUNCTION public.wrap_cube(integer);
