-- Issue #2: the call handler must never write to pg_proc
-- (concurrent callers failed with "tuple concurrently updated").
SET client_min_messages = warning;
CREATE EXTENSION IF NOT EXISTS plpgsql_wrap;
RESET client_min_messages;

CREATE FUNCTION ch_double(i int) RETURNS int LANGUAGE plpgsql_wrap AS $$
BEGIN
    RETURN i * 2;
END
$$;

CREATE TEMP TABLE ch_before AS
    SELECT xmin::text AS x, ctid::text AS t FROM pg_proc WHERE proname = 'ch_double';

SELECT ch_double(21);
SELECT ch_double(i) FROM generate_series(1, 3) i;

-- pg_proc row untouched by calls: same xmin/ctid, still wrapped
SELECT p.xmin::text = b.x AS same_xmin, p.ctid::text = b.t AS same_ctid,
       left(p.prosrc, 14) AS prefix, l.lanname
  FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang, ch_before b
 WHERE p.proname = 'ch_double';

-- recursion: inner calls must see the wrapped source
CREATE FUNCTION ch_fact(n int) RETURNS bigint LANGUAGE plpgsql_wrap AS $$
BEGIN
    IF n <= 1 THEN RETURN 1; END IF;
    RETURN n * ch_fact(n - 1);
END
$$;
SELECT ch_fact(10);

-- polymorphic arguments (needs fn_expr)
CREATE FUNCTION ch_poly(a anyelement) RETURNS anyelement LANGUAGE plpgsql_wrap AS $$
BEGIN
    RETURN a;
END
$$;
SELECT ch_poly(3), ch_poly('x'::text);

-- set-returning function
CREATE FUNCTION ch_srf(n int) RETURNS SETOF int LANGUAGE plpgsql_wrap AS $$
BEGIN
    FOR i IN 1..n LOOP RETURN NEXT i; END LOOP;
END
$$;
SELECT * FROM ch_srf(3);

-- trigger function
CREATE TABLE ch_tab (a int, b text);
CREATE FUNCTION ch_trg() RETURNS trigger LANGUAGE plpgsql_wrap AS $$
BEGIN
    NEW.b := 'trg:' || NEW.a;
    RETURN NEW;
END
$$;
CREATE TRIGGER ch_t BEFORE INSERT ON ch_tab FOR EACH ROW EXECUTE FUNCTION ch_trg();
INSERT INTO ch_tab (a) VALUES (1), (2);
SELECT * FROM ch_tab ORDER BY a;

-- runtime error leaves the function usable and wrapped
CREATE FUNCTION ch_boom() RETURNS int LANGUAGE plpgsql_wrap AS $$
BEGIN
    RAISE EXCEPTION 'boom';
END
$$;
SELECT ch_boom();
SELECT left(prosrc, 14) FROM pg_proc WHERE proname = 'ch_boom';

-- read-only transaction
BEGIN READ ONLY;
SELECT ch_double(5), ch_fact(3);
COMMIT;

-- CREATE OR REPLACE is picked up in the same session
CREATE OR REPLACE FUNCTION ch_double(i int) RETURNS int LANGUAGE plpgsql_wrap AS $$
BEGIN
    RETURN i * 100;
END
$$;
SELECT ch_double(5);

DROP TABLE ch_tab;
DROP FUNCTION ch_double(int), ch_fact(int), ch_poly(anyelement), ch_srf(int),
              ch_trg(), ch_boom();
