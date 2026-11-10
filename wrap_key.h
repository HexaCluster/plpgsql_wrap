/*
 * wrap_key.h  —  compile-time AES-256 key for plpgsql_wrap
 *
 * HOW TO SET YOUR KEY
 * -------------------
 * Option A — edit this file directly:
 *   1.  openssl rand -hex 32
 *   2.  Replace the zeros below with the output.
 *   3.  make clean && make && sudo make install
 *   4.  Restart PostgreSQL.
 *
 * Option B — keep the key out of version control entirely:
 *   make clean
 *   make WRAP_KEY_HEX=$(openssl rand -hex 32)
 *   sudo make install
 *
 * AFTER CHANGING THE KEY
 * ----------------------
 * All existing wrapped procedures must be unwrapped and re-wrapped.
 * The migration helper does this:
 *
 *   -- While OLD .so is still loaded (before restart):
 *   DO $$
 *   DECLARE r record;
 *   BEGIN
 *     FOR r IN SELECT nspname AS schema, proname AS name,
 *                     pg_get_function_identity_arguments(p.oid) AS args
 *              FROM pg_proc p
 *              JOIN pg_namespace n ON n.oid = p.pronamespace
 *              JOIN pg_language  l ON l.oid = p.prolang
 *              WHERE l.lanname = 'plpgsql_wrap'
 *     LOOP
 *         PERFORM plpgsql_wrap.unwrap_procedure('<old key hex>',
 *                                               r.schema, r.name, r.args);
 *     END LOOP;
 *   END;
 *   $$;
 *   -- Then install new .so, restart, and re-create with LANGUAGE plpgsql_wrap.
 *
 * SECURITY
 * --------
 * The build converts this key into XOR-masked byte arrays
 * (wrap_key_data.h, generated): it is not stored as a hex string in the
 * .so and cannot be found with strings(1).  This is obfuscation only:
 * anybody who can read and reverse plpgsql_wrap.so can recover the key,
 * so restrict read access to the installed .so and to wrap_key_data.h.
 * This matches Oracle WRAP: protection is against database-level
 * inspection, not against an OS-level attacker who controls the binary.
 * The default all-zero key below offers no protection at all.
 */

#ifndef WRAP_KEY_H
#define WRAP_KEY_H

/*
 * 64 hex characters = 32 bytes = 256-bit AES key.
 * REPLACE THE ZEROS BEFORE BUILDING FOR PRODUCTION.
 */
#ifndef WRAP_KEY_HEX
#define WRAP_KEY_HEX \
    "0000000000000000000000000000000000000000000000000000000000000000"
#endif

#endif /* WRAP_KEY_H */
