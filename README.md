# plpgsql_wrap

Oracle-WRAP-equivalent procedural language for PostgreSQL.

Write stored procedures with `LANGUAGE plpgsql_wrap`; source is validated, then AES-256-GCM encrypted directly into `pg_proc.prosrc`.

Users cannot look at store procedures plain text source code any more unless they know the encryption key.

`pg_dump` will not expose store procedures plain text source code too and the `pg_dump` output is directly restorable.  Pre-wrapped blobs are accepted at `CREATE` time.

## Installation

```bash
# 1. Generate a key (keep it out of git with make-time override)
export WRAP_KEY_HEX=$(openssl rand -hex 32)
echo $WRAP_KEY_HEX # backup the key to be able to unwrap your stored procedure
make WRAP_KEY_HEX=$WRAP_KEY_HEX
sudo make install

# 2. In each database
CREATE EXTENSION plpgsql_wrap;   -- requires plpgsql
```

The key is not compiled in as a hex string: the build generates
`wrap_key_data.h` holding it as XOR-masked bytes.  Never commit that file.
Once `make WRAP_KEY_HEX=...` has been run, a plain `sudo make install`
keeps the key used at build time.  Building with the default all-zero key
prints a warning, and every `CREATE FUNCTION ... LANGUAGE plpgsql_wrap`
then raises a WARNING: code wrapped with that key is not protected.

### Upgrading from 1.0

Version 1.1 fixes two security issues of the 1.0 SQL objects (see
"Security notes").  After installing the new library, in each database:

```sql
ALTER EXTENSION plpgsql_wrap UPDATE TO '1.1';
```

---
## Creating a wrapped function

Identical to LANGUAGE plpgsql, only the language name differs: plpgsql_wrap.

```sql
CREATE OR REPLACE FUNCTION public.calculate_bonus(emp_id int, yr int)
RETURNS numeric
LANGUAGE plpgsql_wrap
AS $$
DECLARE
    v_salary numeric;
BEGIN
    SELECT salary INTO v_salary FROM employees WHERE id = emp_id;
    RETURN v_salary * 0.15;   -- confidential formula
END;
$$;

-- Calling, permissions, overloading — all identical to plpgsql:
SELECT calculate_bonus(42, 2024);
```
In pg_proc the code is obfuscated:
```
SELECT substring(prosrc, 1, 50)||'...' AS wrapped_code
    FROM pg_proc WHERE proname = 'calculate_bonus';
                     wrapped_code                      
-------------------------------------------------------
 PLPGSQLWRAP:1:5752415001f5db365c6c185b66081ff0a23d...
(1 line)
```
This is also what will appears in the `pg_dump` output.

---

## Unwrapping (superuser only)

It is possible to recover plain text code of a wrapped stored procedure by using the `plpgsql_wrap.unwrap_procedure` function. It requires to be superuser and to provide the encryption key registered at compile time in the .so library.

```sql
-- Convert back to plain LANGUAGE plpgsql permanently:
SELECT plpgsql_wrap.unwrap_procedure('myhexkey', 'public', 'calculate_bonus');

-- After this:
SELECT prolang::regtype FROM pg_proc WHERE proname = 'calculate_bonus';
-- → plpgsql

SELECT prosrc FROM pg_proc WHERE proname = 'calculate_bonus';
-- → plain PL/pgSQL source
```

If you have overloaded functions, you need to distinguish them passing the parameters:

```sql
-- Convert back to plain LANGUAGE plpgsql permanently:
SELECT plpgsql_wrap.unwrap_procedure('myhexkey', 'public', 'calculate_bonus', 'emp_id integer, yr integer');
```


---

## What happens at `CREATE FUNCTION` time

The validator hook runs at the end of the `CREATE FUNCTION` command, inside the same transaction.

### Plain path (new or replacement source)

```
User writes plain PL/pgSQL in AS $$ ... $$
        │
        ▼  pgwrap_validator() called by PostgreSQL
        │
        ├─ 1. Read prosrc from pg_proc  (plain PL/pgSQL)
        │
        ├─ 2. Call plpgsql_validator(fn_oid)
        │       Syntax error? → ereport → whole txn rolls back
        │       User sees a normal PL/pgSQL syntax error
        │
        ├─ 3. AES-256-GCM encrypt(source, compile_time_key)
        │
        └─ 4. UPDATE pg_proc SET prosrc = 'PLPGSQLWRAP:1:<hex>'
               The live pg_proc row only holds the blob, but the plain
               source was written by CREATE FUNCTION itself: see
               "Security notes" below.
```

### Wrapped path (pg_restore or pre-wrapped input)

```
AS $$ body starts with "PLPGSQLWRAP:1:"
        │
        ▼  pgwrap_validator() called by PostgreSQL
        │
        ├─ 1. Hex-decode the blob
        │
        ├─ 2. AES-256-GCM authenticate (tag check, compile-time key)
        │       Wrong key / tampered? → ereport → txn rolls back
        │
        └─ 3. prosrc is already correct — nothing to write
               (pg_dump output accepted directly)
```

---

## pg_dump / pg_restore lifecycle

### What pg_dump produces

```sql
-- pg_dump output (excerpt):
CREATE OR REPLACE FUNCTION public.calculate_bonus(emp_id integer, yr integer)
RETURNS numeric
LANGUAGE plpgsql_wrap
AS $$
PLPGSQLWRAP:1:5752415001a3f1c9d2e6b70481...long hex string...9b2c
$$;
```

The hex string is the raw EPGP blob stored in `pg_proc.prosrc`, verbatim.

### Running the dump on a target server

```bash
# Plain SQL restore:
psql -d targetdb -f dump.sql

# pg_restore:
pg_restore -d targetdb dump.custom
```

The validator sees `PLPGSQLWRAP:1:` → authenticates → accepts. **No extra steps required** as long as the same `.so` (same compile-time key) is installed.

### Restore with a different key

If the target server has a different compile-time key, the GCM tag check fails at first call time (not at restore time — the validator only authenticates, it does not require the key to be valid for another server's key). To migrate:

1. On the **source** server, unwrap all functions before dumping:
   ```sql
   SELECT plpgsql_wrap.unwrap_procedure('myhexkey', schema, func_name)
   FROM   plpgsql_wrap.list_wrapped();
   ```
2. `pg_dump` the database (functions are now plain `plpgsql`).
3. restore on the target by replacing `LANGUAGE plpgsql` with `LANGUAGE plpgsql_wrap` in the CREATE FUNCTION code.

---

## Pre-wrapped input

Any tool that generates wrapped blobs (e.g. a build pipeline that wraps source before deployment) can supply them directly to `CREATE FUNCTION`:

```sql
CREATE OR REPLACE FUNCTION public.my_func(x integer)
RETURNS integer
LANGUAGE plpgsql_wrap
AS $$
PLPGSQLWRAP:1:<hex-blob-generated-by-your-tool>
$$;
```

This mirrors Oracle's `CREATE OR REPLACE PROCEDURE ... WRAPPED <blob>` syntax. The validator authenticates the blob and stores it — no re-encryption, no source visibility.

---

## prosrc format

```
"PLPGSQLWRAP:1:" + lowercase_hex( raw_blob )

raw_blob layout:
  Offset  Len  Field
  ------  ---  -----
       0    4  magic    "WRAP"
       4    1  version  0x01
       5   12  nonce    random AES-GCM nonce (new per wrap)
      17   16  tag      AES-GCM authentication tag
      33    N  ciphertext
```

Plain hex keeps `prosrc` valid ASCII in all PostgreSQL text contexts: `pg_dump`, streaming replication, logical replication, `COPY`, `pg_upgrade`.

---

## Security model

| Threat | Result |
|---|---|
| `SELECT prosrc FROM pg_proc` | `PLPGSQLWRAP:1:<hex>` — no plaintext |
| `\sf` / `pg_get_functiondef()` | Returns opaque wrapped string |
| `pg_dump` output | Contains encrypted blob — useless without the `.so` |
| `pg_restore` on matching server | Works transparently |
| `pg_restore` on server with wrong key | Blob stored OK; first call fails with auth error |
| Tampered blob in dump | GCM tag rejects at first call |
| Syntax error in plain source | Rejected before encryption; `CREATE` rolls back |

## Authors

- Gilles Darold < gilles AT darold DOT net >

## License

This extension is free software distributed under the PostgreSQL Licence.

        Copyright (c) 2026, Hexacluster Corp.

---

## Security notes

### What is protected

The source code stored in `pg_proc.prosrc`, and therefore in `pg_dump`
output, is encrypted.  A user reading the catalog, `pg_get_functiondef()`
or a dump only sees the `PLPGSQLWRAP:1:` blob.

### What is not protected

Like Oracle WRAP, this is protection against database-level inspection,
not against somebody controlling the server:

* **The key is inside `plpgsql_wrap.so`.**  It is masked so that
  `strings(1)` does not reveal it, but anybody able to read and reverse the
  library can recover it.  Restrict read access to the installed `.so`, to
  the build tree (`wrap_key_data.h`) and to packages built from it.
* **`CREATE FUNCTION` with plain source.**  PostgreSQL first stores the
  plain source in `pg_proc`, then the validator replaces it with the blob in
  the same transaction.  The plain source therefore reaches the WAL (and
  archives, replicas), stays in a dead `pg_proc` tuple until VACUUM, and is
  visible wherever the statement text is recorded: `log_statement`,
  `pg_stat_statements` (`track_utility`), `pg_stat_activity`.  For
  sensitive code, deploy pre-wrapped blobs (see "Pre-wrapped input").
* **Runtime messages.**  Error `CONTEXT` lines show the text of the SQL
  statement that failed inside a wrapped function to the caller, e.g.
  `SQL statement "select (x * 1337 + 42) / (x - 1)"`.  SQL statements run
  by wrapped functions are also visible to `pg_stat_statements.track = all`
  and `auto_explain.log_nested_statements`.
* **`unwrap_procedure()` takes the key as an argument.**  Errors raised by
  it never log the statement, but `log_statement = 'all'` (or `'mod'`)
  logs it before execution, and it is visible in `pg_stat_activity` while
  it runs.  Disable statement logging for the session before calling it.

### Privileges

* The language is untrusted: only superusers can create wrapped functions.
* `plpgsql_wrap.validator(oid)` is not executable by PUBLIC, and checks
  that the target is a `plpgsql_wrap` function the caller may execute.
  In 1.0 any user with `USAGE` on the `plpgsql_wrap` schema could call it
  on functions of other languages and destroy them.
* `plpgsql_wrap.verify_blob()` performs the real AES-256-GCM check and is
  not `SECURITY DEFINER`.  In 1.0 it was a `SECURITY DEFINER` function
  without a fixed `search_path`, which allowed privilege escalation to
  superuser.
* `plpgsql_wrap.unwrap_procedure()` is superuser only and checks the
  privilege before the key, which is compared in constant time.

