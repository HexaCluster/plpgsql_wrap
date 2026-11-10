/*
 * plpgsql_wrap.c
 *
 * Oracle-WRAP-equivalent procedural language "plpgsql_wrap" for PostgreSQL.
 *
 * DESIGN GOALS
 * ============
 *
 * 1. Transparent wrapping at DDL time.
 *    Only the language name changes for the user:
 *      LANGUAGE plpgsql_wrap
 *    The validator intercepts the CREATE, validates the plain source via
 *    PL/pgSQL's own validator, encrypts it with AES-256-GCM, and writes
 *    the ciphertext directly into pg_proc.prosrc.  No side tables.
 *
 * 2. pg_dump / pg_restore safe.
 *    pg_dump reads pg_proc.prosrc verbatim and emits:
 *
 *      CREATE OR REPLACE FUNCTION ... LANGUAGE plpgsql_wrap AS $$
 *      PLPGSQLWRAP:1:<hex>
 *      $$;
 *
 *    pg_restore runs that SQL; the validator sees the prefix, authenticates
 *    the blob (GCM tag check), and stores it unchanged  --  no re-encryption,
 *    no plaintext exposure anywhere in the restore stream.
 *
 * 3. Pre-wrapped input accepted at CREATE time (Oracle-style deployment).
 *    A CI/CD pipeline or DBA may wrap source externally and supply the
 *    blob as the AS $$ body.  Treated identically to the restore path.
 *
 * 4. Direct plpgsql invocation (no pg_temp, no SPI round-trip, no catalog
 *    write at execution time).
 *    The call handler never modifies pg_proc.  The decrypted source is
 *    exposed to plpgsql_compile() only, through a backend-local, in-memory
 *    substitution of the pinned PROCOID syscache entry, then the real
 *    plpgsql call handler is invoked via fmgr.  plpgsql compiles and caches
 *    the function through its own internal cache, keyed on the real
 *    pg_proc row (xmin/ctid), so it is compiled once per session.
 *
 * 5. Inline handler (DO blocks).
 *    LANGUAGE plpgsql_wrap works in DO $$ ... $$ blocks; the body is
 *    decrypted (if wrapped) or validated and executed directly.
 *
 * VALIDATOR DECISION TREE
 * =======================
 *
 *   prosrc in pg_proc after PostgreSQL writes the AS $$ body
 *         │
 *         ├── starts with "PLPGSQLWRAP:1:" ?
 *         │         │
 *         │    YES ─┘   [WRAPPED PATH  --  pg_restore / pre-wrapped input]
 *         │              1. Hex-decode blob
 *         │              2. AES-256-GCM authenticate (tag check, compile key)
 *         │                 wrong key / tampered -> ereport ERROR
 *         │              3. prosrc already correct; nothing to write
 *         │
 *         └── NO        [PLAIN PATH  --  developer writing new source]
 *                        1. Temporarily set pg_proc.prolang = plpgsql
 *                           (plpgsql_validator rejects functions whose
 *                            prolang ≠ its own language OID)
 *                        2. Call plpgsql_validator(fn_oid)
 *                           syntax error -> ereport ERROR -> whole txn rolls back
 *                        3. Restore pg_proc.prolang = plpgsql_wrap
 *                        4. AES-256-GCM encrypt plain source
 *                        5. Write "PLPGSQLWRAP:1:<hex>" back to pg_proc.prosrc
 *
 * CALL HANDLER STRATEGY
 * =====================
 *   1. Pin the PROCOID syscache entry, decrypt prosrc -> plain source
 *   2. Point the pinned entry's t_data at an in-memory copy of the row
 *      carrying the plain source (original xmin/ctid kept)
 *   3. Call plpgsql_compile(): compiles, or reuses its valid cached copy
 *   4. Restore the syscache entry, wipe the plain copy, unpin
 *   5. Invoke plpgsql_call_handler() via fmgr to execute the body
 *   No pg_proc update: safe under concurrency (issue #2), on hot standby,
 *   and the plain source never reaches the heap or the WAL.
 *
 * PROSRC FORMAT
 * =============
 *
 *   "PLPGSQLWRAP:1:" + lowercase_hex( raw_blob )
 *
 *   raw_blob:
 *     [0..3]    magic      "WRAP"   (4 bytes, not NUL terminated)
 *     [4]       version    0x01     (1 byte)
 *     [5..16]   nonce      random   (12 bytes)
 *     [17..32]  tag                 (16 bytes)
 *     [33..]    ciphertext          (N bytes)
 *
 *   Fixed header: 33 bytes.  Prefix in prosrc: 14 chars ("PLPGSQLWRAP:1:").
 *
 * PER-SESSION CACHE
 * =================
 *   The call handler caches via fcinfo->flinfo->fn_extra, keyed on fn_oid.
 *   The cached struct records:
 *     - The OID and the pg_proc syscache generation at wrap time
 *     - The name of the permanent pg_temp dispatch function
 *   On invalidation (pg_proc changes), the cache entry is dropped and the
 *   dispatch function is re-created.
 *
 * COMPILE-TIME KEY
 * ================
 *   Defined as WRAP_KEY_HEX in wrap_key.h (64 hex chars = 32 bytes).
 *   Override at build time:  make WRAP_KEY_HEX=<64 hex chars>
 *
 * BUILD
 * =====
 *   make && sudo make install
 *   Requires: PostgreSQL headers >= 12, OpenSSL >= 1.1
 *
 * Original Author : Gilles Darold <gilles@darold.net>
 * IA              : IA drive, code review and fixes by the author.
 * Licence         : PostgreSQL
 * Copyright (c) 2026, Hexacluster Corp.
 */

#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_language.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/event_trigger.h"
#include "executor/spi.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/syscache.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

PG_MODULE_MAGIC;

/* ====================================================================
 * Compile-time key
 * ==================================================================== */
#include "wrap_key.h"

/* ====================================================================
 * Wire-format constants
 * ==================================================================== */
#define WRAP_MAGIC          "WRAP"
#define WRAP_MAGIC_LEN      4
#define WRAP_VERSION_BYTE   0x01
#define WRAP_NONCE_LEN      12
#define WRAP_TAG_LEN        16
#define WRAP_KEY_LEN        32
#define WRAP_HDR_LEN        (WRAP_MAGIC_LEN + 1 + WRAP_NONCE_LEN + WRAP_TAG_LEN) /* 33 */

#define PROSRC_PREFIX       "PLPGSQLWRAP:1:"
#define PROSRC_PREFIX_LEN   14   /* strlen("PLPGSQLWRAP:1:") */

/* ====================================================================
 * Per-session function cache entry
 *
 * Stored in fn_extra (allocated in fn_mcxt, which survives the call).
 * Caches the OIDs needed to invoke plpgsql directly so we only look
 * them up once per session per function.
 * ==================================================================== */
/* plpgsql_compile(FunctionCallInfo, bool) -- PGDLLEXPORT'ed by plpgsql */
typedef void *(*plpgsql_compile_fn) (FunctionCallInfo fcinfo, bool forValidator);

typedef struct WrapCacheEntry
{
    Oid     fn_oid;             /* function OID this entry is for           */
    Oid     plpgsql_call_oid;   /* OID of plpgsql_call_handler()            */
    Oid     plpgsql_lang_oid;   /* OID of the plpgsql language              */
    plpgsql_compile_fn plpgsql_compile; /* plpgsql's compiler entry point   */
    FmgrInfo plpgsql_flinfo;    /* persistent flinfo used to call plpgsql;
                                 * its fn_extra holds plpgsql's compiled
                                 * function for this call site             */
} WrapCacheEntry;

/* ====================================================================
 * Key initialisation
 * ==================================================================== */
static uint8_t g_key[WRAP_KEY_LEN];
static bool    g_key_ready = false;

void _PG_init(void);

void
_PG_init(void)
{
    const char *hex = WRAP_KEY_HEX;
    int         i;

    if (strlen(hex) != WRAP_KEY_LEN * 2)
        ereport(FATAL,
                (errcode(ERRCODE_CONFIG_FILE_ERROR),
                 errmsg("plpgsql_wrap: WRAP_KEY_HEX must be exactly 64 hex chars "
                        "(got %zu)", strlen(hex))));

    for (i = 0; i < WRAP_KEY_LEN; i++)
    {
        unsigned int b;
        if (sscanf(hex + 2*i, "%02x", &b) != 1)
            ereport(FATAL,
                    (errcode(ERRCODE_CONFIG_FILE_ERROR),
                     errmsg("plpgsql_wrap: invalid hex at position %d in WRAP_KEY_HEX",
                            2*i)));
        g_key[i] = (uint8_t) b;
    }
    g_key_ready = true;
}

/* ====================================================================
 * AES-256-GCM encrypt
 *
 * Returns palloc'd byte buffer of length *out_len.
 * Layout: [WRAP_HDR][ciphertext]
 * ==================================================================== */
static uint8_t *
aes_encrypt(const char *plaintext, int plen, int *out_len)
{
    uint8_t         nonce[WRAP_NONCE_LEN];
    uint8_t         tag[WRAP_TAG_LEN];
    uint8_t        *buf, *body;
    EVP_CIPHER_CTX *ctx = NULL;
    int             olen = 0, tlen = 0;

    Assert(g_key_ready);

    if (RAND_bytes(nonce, WRAP_NONCE_LEN) != 1)
        ereport(ERROR, (errmsg("plpgsql_wrap: RAND_bytes failed")));

    buf  = palloc0(WRAP_HDR_LEN + plen + EVP_MAX_BLOCK_LENGTH);
    body = buf + WRAP_HDR_LEN;

    memcpy(buf, WRAP_MAGIC, WRAP_MAGIC_LEN);
    buf[WRAP_MAGIC_LEN] = WRAP_VERSION_BYTE;
    memcpy(buf + WRAP_MAGIC_LEN + 1, nonce, WRAP_NONCE_LEN);
    /* tag slot at [WRAP_MAGIC_LEN+1+WRAP_NONCE_LEN], filled after encrypt */

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto ossl_err;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto ossl_err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WRAP_NONCE_LEN, NULL)) goto ossl_err;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, g_key, nonce)) goto ossl_err;
    if (!EVP_EncryptUpdate(ctx, body, &olen, (const uint8_t *)plaintext, plen)) goto ossl_err;
    if (!EVP_EncryptFinal_ex(ctx, body + olen, &tlen)) goto ossl_err;
    olen += tlen;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, WRAP_TAG_LEN, tag)) goto ossl_err;
    EVP_CIPHER_CTX_free(ctx);

    memcpy(buf + WRAP_MAGIC_LEN + 1 + WRAP_NONCE_LEN, tag, WRAP_TAG_LEN);
    *out_len = WRAP_HDR_LEN + olen;
    return buf;

ossl_err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    ereport(ERROR,
            (errmsg("plpgsql_wrap: OpenSSL encrypt error: %s",
                    ERR_reason_error_string(ERR_get_error()))));
    return NULL;
}

/* ====================================================================
 * AES-256-GCM decrypt
 *
 * Returns palloc'd NUL-terminated plaintext.
 * Raises ERROR if magic/version wrong or GCM tag fails.
 * ==================================================================== */
static char *
aes_decrypt(const uint8_t *blob, int blen)
{
    const uint8_t  *nonce, *tag, *ciphertext;
    int             clen;
    uint8_t        *plain;
    EVP_CIPHER_CTX *ctx = NULL;
    int             olen = 0, tlen = 0;

    Assert(g_key_ready);

    if (blen < WRAP_HDR_LEN)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("plpgsql_wrap: blob too short "
                        "(%d bytes, minimum %d)", blen, WRAP_HDR_LEN)));

    if (memcmp(blob, WRAP_MAGIC, WRAP_MAGIC_LEN) != 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("plpgsql_wrap: invalid magic  --  not a WRAP blob")));

    if (blob[WRAP_MAGIC_LEN] != WRAP_VERSION_BYTE)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("plpgsql_wrap: unsupported blob version 0x%02x",
                        blob[WRAP_MAGIC_LEN])));

    nonce      = blob + WRAP_MAGIC_LEN + 1;
    tag        = nonce + WRAP_NONCE_LEN;
    ciphertext = tag   + WRAP_TAG_LEN;
    clen       = blen  - WRAP_HDR_LEN;

    plain = (uint8_t *) palloc(clen + 1);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto ossl_err;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto ossl_err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WRAP_NONCE_LEN, NULL)) goto ossl_err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, g_key, nonce)) goto ossl_err;
    if (!EVP_DecryptUpdate(ctx, plain, &olen, ciphertext, clen)) goto ossl_err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             WRAP_TAG_LEN, (void *)tag)) goto ossl_err;

    if (EVP_DecryptFinal_ex(ctx, plain + olen, &tlen) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                 errmsg("plpgsql_wrap: authentication failed  --  "
                        "wrong compile-time key or tampered blob")));
    }
    olen += tlen;
    EVP_CIPHER_CTX_free(ctx);

    plain[olen] = '\0';
    return (char *) plain;

ossl_err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    ereport(ERROR,
            (errmsg("plpgsql_wrap: OpenSSL decrypt error: %s",
                    ERR_reason_error_string(ERR_get_error()))));
    return NULL;
}

/*
 * aes_authenticate_only: full GCM decrypt but discard the plaintext.
 * Used by the validator's wrapped path and by pgwrap_verify_blob().
 * Returns true on success, raises ERROR on failure.
 */
static void
aes_authenticate_only(const uint8_t *blob, int blen)
{
    char *plain = aes_decrypt(blob, blen);
    /* Wipe immediately  --  we only needed the auth check */
    explicit_bzero(plain, strlen(plain));
    pfree(plain);
}

/* ====================================================================
 * prosrc encoding / decoding
 * ==================================================================== */

/*
 * blob_to_prosrc: raw bytes -> "PLPGSQLWRAP:1:" + hex
 * Returns palloc'd C string.
 */
static char *
blob_to_prosrc(const uint8_t *blob, int blen)
{
    char *out = palloc(PROSRC_PREFIX_LEN + blen * 2 + 1);
    char *p   = out;
    int   i;

    memcpy(p, PROSRC_PREFIX, PROSRC_PREFIX_LEN);
    p += PROSRC_PREFIX_LEN;

    for (i = 0; i < blen; i++)
    {
        static const char hx[] = "0123456789abcdef";
        *p++ = hx[(blob[i] >> 4) & 0xF];
        *p++ = hx[ blob[i]       & 0xF];
    }
    *p = '\0';
    return out;
}

/*
 * prosrc_to_blob: prosrc -> raw bytes + *out_len.
 * Returns NULL if prosrc does not start with PROSRC_PREFIX.
 * Trims trailing whitespace / newlines that pg_dump may append.
 */
static uint8_t *
prosrc_to_blob(const char *prosrc, int *out_len)
{
    const char *hex;
    int         hexlen, i;
    uint8_t    *buf;

    if (strncmp(prosrc, PROSRC_PREFIX, PROSRC_PREFIX_LEN) != 0)
        return NULL;

    hex    = prosrc + PROSRC_PREFIX_LEN;
    hexlen = strlen(hex);

    /* Trim whitespace pg_dump or editors may append after the hex */
    while (hexlen > 0 && (hex[hexlen-1] == '\n' || hex[hexlen-1] == '\r' ||
                           hex[hexlen-1] == ' '  || hex[hexlen-1] == '\t'))
        hexlen--;

    if (hexlen == 0 || hexlen % 2 != 0)
        ereport(ERROR,
                (errcode(ERRCODE_DATA_CORRUPTED),
                 errmsg("plpgsql_wrap: malformed wrapped prosrc "
                        "(odd or empty hex payload)")));

    *out_len = hexlen / 2;
    buf      = palloc(*out_len);

    for (i = 0; i < *out_len; i++)
    {
        unsigned int b;
        if (sscanf(hex + 2*i, "%02x", &b) != 1)
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_CORRUPTED),
                     errmsg("plpgsql_wrap: invalid hex char in prosrc "
                            "at position %d", 2*i)));
        buf[i] = (uint8_t) b;
    }
    return buf;
}

/* ====================================================================
 * Catalog helpers
 * ==================================================================== */

/*
 * update_prosrc: overwrite pg_proc.prosrc for fn_oid.
 * Must be called within the same transaction as the CREATE FUNCTION.
 */
static void
update_prosrc(Oid fn_oid, const char *new_prosrc)
{
    Relation  rel;
    HeapTuple tup, newtup;
    Datum     values[Natts_pg_proc];
    bool      nulls[Natts_pg_proc];
    bool      replaces[Natts_pg_proc];

    rel = table_open(ProcedureRelationId, RowExclusiveLock);

    tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(tup))
    {
        table_close(rel, RowExclusiveLock);
        ereport(ERROR,
                (errmsg("plpgsql_wrap: pg_proc lookup failed for %u",
                        fn_oid)));
    }

    memset(values,   0, sizeof(values));
    memset(nulls,    false, sizeof(nulls));
    memset(replaces, false, sizeof(replaces));

    values[Anum_pg_proc_prosrc - 1]   = CStringGetTextDatum(new_prosrc);
    replaces[Anum_pg_proc_prosrc - 1] = true;

    newtup = heap_modify_tuple(tup, RelationGetDescr(rel),
                               values, nulls, replaces);
    CatalogTupleUpdate(rel, &newtup->t_self, newtup);

    heap_freetuple(newtup);
    heap_freetuple(tup);
    table_close(rel, RowExclusiveLock);
    CacheInvalidateCatalog(ProcedureRelationId);
}

/*
 * update_prosrc_and_lang: overwrite both pg_proc.prosrc and pg_proc.prolang.
 * Used by unwrap_procedure() to switch the function to plain plpgsql.
 */
static void
update_prosrc_and_lang(Oid fn_oid, const char *new_prosrc, Oid new_lang)
{
    Relation  rel;
    HeapTuple tup, newtup;
    Datum     values[Natts_pg_proc];
    bool      nulls[Natts_pg_proc];
    bool      replaces[Natts_pg_proc];

    rel = table_open(ProcedureRelationId, RowExclusiveLock);

    tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(tup))
    {
        table_close(rel, RowExclusiveLock);
        ereport(ERROR,
                (errmsg("plpgsql_wrap: pg_proc lookup failed for %u",
                        fn_oid)));
    }

    memset(values,   0, sizeof(values));
    memset(nulls,    false, sizeof(nulls));
    memset(replaces, false, sizeof(replaces));

    values[Anum_pg_proc_prosrc  - 1]   = CStringGetTextDatum(new_prosrc);
    replaces[Anum_pg_proc_prosrc - 1]  = true;
    values[Anum_pg_proc_prolang - 1]   = ObjectIdGetDatum(new_lang);
    replaces[Anum_pg_proc_prolang - 1] = true;

    newtup = heap_modify_tuple(tup, RelationGetDescr(rel),
                               values, nulls, replaces);
    CatalogTupleUpdate(rel, &newtup->t_self, newtup);

    heap_freetuple(newtup);
    heap_freetuple(tup);
    table_close(rel, RowExclusiveLock);
    CacheInvalidateCatalog(ProcedureRelationId);
}

/*
 * update_lang: overwrite only pg_proc.prolang for fn_oid.
 * Used to temporarily masquerade as plpgsql before calling
 * plpgsql_validator, then restored to plpgsql_wrap afterward.
 */
static void
update_lang(Oid fn_oid, Oid new_lang)
{
    Relation  rel;
    HeapTuple tup, newtup;
    Datum     values[Natts_pg_proc];
    bool      nulls[Natts_pg_proc];
    bool      replaces[Natts_pg_proc];

    rel = table_open(ProcedureRelationId, RowExclusiveLock);

    tup = SearchSysCacheCopy1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(tup))
    {
        table_close(rel, RowExclusiveLock);
        ereport(ERROR,
                (errmsg("plpgsql_wrap: pg_proc lookup failed for %u",
                        fn_oid)));
    }

    memset(values,   0, sizeof(values));
    memset(nulls,    false, sizeof(nulls));
    memset(replaces, false, sizeof(replaces));

    values[Anum_pg_proc_prolang - 1]   = ObjectIdGetDatum(new_lang);
    replaces[Anum_pg_proc_prolang - 1] = true;

    newtup = heap_modify_tuple(tup, RelationGetDescr(rel),
                               values, nulls, replaces);
    CatalogTupleUpdate(rel, &newtup->t_self, newtup);

    heap_freetuple(newtup);
    heap_freetuple(tup);
    table_close(rel, RowExclusiveLock);
    CacheInvalidateCatalog(ProcedureRelationId);
}

/* Returns OID of the "plpgsql" language; errors if not found. */
static Oid
get_plpgsql_lang_oid(void)
{
    HeapTuple tup;
    Oid       oid;

    tup = SearchSysCache1(LANGNAME, CStringGetDatum("plpgsql"));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("plpgsql_wrap: language \"plpgsql\" not found  --  "
                        "is plpgsql installed?")));
    oid = ((Form_pg_language) GETSTRUCT(tup))->oid;
    ReleaseSysCache(tup);
    return oid;
}

/* Returns OID of plpgsql's own validator function. */
static Oid
get_plpgsql_validator_oid(void)
{
    HeapTuple        tup;
    Form_pg_language lf;
    Oid              val_oid;

    tup = SearchSysCache1(LANGNAME, CStringGetDatum("plpgsql"));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("plpgsql_wrap: language \"plpgsql\" not found")));
    lf      = (Form_pg_language) GETSTRUCT(tup);
    val_oid = lf->lanvalidator;
    ReleaseSysCache(tup);

    if (!OidIsValid(val_oid))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("plpgsql_wrap: plpgsql has no validator function")));
    return val_oid;
}

/* ====================================================================
 * VALIDATOR
 *
 * Called by PostgreSQL at the end of CREATE [OR REPLACE] FUNCTION when
 * the language is plpgsql_wrap.  pg_proc already has a row for fn_oid;
 * prosrc holds whatever the user supplied in the AS $$ ... $$ body.
 *
 * WRAPPED PATH (prosrc starts with PROSRC_PREFIX):
 *   The input is already an encrypted blob  --  from pg_restore, from a
 *   pre-wrapped deployment, or (rarely) from a CREATE OR REPLACE where
 *   the developer explicitly supplies a blob.
 *   Action: authenticate the GCM tag; accept prosrc as-is.
 *
 * PLAIN PATH (prosrc is ordinary PL/pgSQL source):
 *   The developer wrote plain source in the AS $$ body.
 *   Action: validate -> encrypt -> write blob back to pg_proc.prosrc.
 * ==================================================================== */
PG_FUNCTION_INFO_V1(pgwrap_validator);
Datum
pgwrap_validator(PG_FUNCTION_ARGS)
{
    Oid         fn_oid = PG_GETARG_OID(0);
    HeapTuple   tup;
    char       *prosrc;
    bool        attr_isnull;
    Datum       prosrc_datum;

    /* ---- Read prosrc from pg_proc ------------------------------ */
    tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR,
                (errmsg("plpgsql_wrap: cache lookup failed for OID %u",
                        fn_oid)));

    prosrc_datum = SysCacheGetAttr(PROCOID, tup,
                                   Anum_pg_proc_prosrc, &attr_isnull);
    if (attr_isnull)
    {
        ReleaseSysCache(tup);
        ereport(ERROR,
                (errmsg("plpgsql_wrap: prosrc is NULL for OID %u", fn_oid)));
    }

    prosrc = TextDatumGetCString(prosrc_datum);
    ReleaseSysCache(tup);

    /* ---- Dispatch on input shape ------------------------------- */
    {
        int      blen;
        uint8_t *blob = prosrc_to_blob(prosrc, &blen);

        if (blob != NULL)
        {
            /* ===========================================
             * WRAPPED PATH
             * Input is a PLPGSQLWRAP:1: blob.
             * Authenticate; do not re-encrypt.
             * =========================================== */
            aes_authenticate_only(blob, blen);
            pfree(blob);
            pfree(prosrc);
            PG_RETURN_VOID();
        }
    }

    /* ===========================================
     * PLAIN PATH
     * prosrc is ordinary PL/pgSQL source.
     * Validate with plpgsql, then encrypt.
     * =========================================== */

    /*
     * Step 1: call plpgsql's own validator.
     *
     * plpgsql_validator checks that the function it is asked to validate
     * actually belongs to the plpgsql language (it compares fn_oid's prolang
     * against its own language OID).  Since our function has
     * prolang = plpgsql_wrap, that check would fail with:
     *   "language validation function NNN called for language NNN instead of NNN"
     *
     * Fix: temporarily set prolang = plpgsql in pg_proc, call the validator,
     * then immediately restore prolang = plpgsql_wrap.
     * All three writes happen in the same transaction; on any error the whole
     * transaction rolls back, leaving pg_proc consistent.
     *
     * We must flush the syscache between each write so the validator and our
     * subsequent restore read the correct current value.
     */
    {
        Oid       plpgsql_lang_oid = get_plpgsql_lang_oid();
        Oid       wrap_lang_oid;
        Oid       val_oid;
        FmgrInfo  flinfo;
        LOCAL_FCINFO(inner, 1);

        /* Resolve our own language OID (plpgsql_wrap) from pg_proc */
        {
            HeapTuple t = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn_oid));
            if (!HeapTupleIsValid(t))
                ereport(ERROR,
                        (errmsg("plpgsql_wrap: pg_proc lookup failed "
                                "for OID %u (lang read)", fn_oid)));
            wrap_lang_oid = ((Form_pg_proc) GETSTRUCT(t))->prolang;
            ReleaseSysCache(t);
        }

        val_oid = get_plpgsql_validator_oid();

        /* Temporarily pretend this function belongs to plpgsql */
        update_lang(fn_oid, plpgsql_lang_oid);
        CommandCounterIncrement();   /* flush so validator sees prolang=plpgsql */

        fmgr_info(val_oid, &flinfo);
        InitFunctionCallInfoData(*inner, &flinfo, 1,
                                 InvalidOid, NULL, NULL);
        inner->args[0].value  = ObjectIdGetDatum(fn_oid);
        inner->args[0].isnull = false;

        /*
         * Call plpgsql_validator.
         * Syntax error -> ereport(ERROR) -> whole txn rolls back ->
         * pg_proc row is gone; user sees a normal PL/pgSQL syntax error.
         *
         * On success we must restore prolang immediately after.
         */
        (void) FunctionCallInvoke(inner);

        /* Restore prolang = plpgsql_wrap */
        update_lang(fn_oid, wrap_lang_oid);
        CommandCounterIncrement();   /* flush so subsequent writes see correct row */
    }

    /* Step 2: encrypt */
    {
        int      blen;
        uint8_t *blob      = aes_encrypt(prosrc, strlen(prosrc), &blen);
        char    *new_prosrc = blob_to_prosrc(blob, blen);
        pfree(blob);

        /* Wipe the plain source from memory before writing the blob */
        explicit_bzero(prosrc, strlen(prosrc));
        pfree(prosrc);

        /* Step 3: write wrapped prosrc back to pg_proc */
        update_prosrc(fn_oid, new_prosrc);
        pfree(new_prosrc);
    }

    PG_RETURN_VOID();
}

/* ====================================================================
 * INLINE HANDLER
 *
 * Called for  DO $$ ... $$ LANGUAGE plpgsql_wrap;
 *
 * The body may be:
 *   a) plain PL/pgSQL  --  decrypt is not needed, execute directly via
 *      the real plpgsql inline handler.
 *   b) a PLPGSQLWRAP:1: blob  --  decrypt first, then execute.
 *
 * We locate plpgsql's inline handler via pg_language.laninline.
 * ==================================================================== */
PG_FUNCTION_INFO_V1(pgwrap_inline_handler);
Datum
pgwrap_inline_handler(PG_FUNCTION_ARGS)
{
    InlineCodeBlock *codeblock = (InlineCodeBlock *) DatumGetPointer(PG_GETARG_DATUM(0));
    InlineCodeBlock  inner_block;
    HeapTuple        lang_tup;
    Form_pg_language lang_form;
    Oid              plpgsql_inline_oid;
    FmgrInfo         flinfo;
    LOCAL_FCINFO(inner_fcinfo, 1);
    char            *source;
    bool             source_is_palloc = false;

    Assert(IsA(codeblock, InlineCodeBlock));

    source = codeblock->source_text;

    /* If the source is a wrapped blob, decrypt it first */
    {
        int      blen;
        uint8_t *blob = prosrc_to_blob(source, &blen);

        if (blob != NULL)
        {
            source = aes_decrypt(blob, blen);
            pfree(blob);
            source_is_palloc = true;
        }
    }

    /* Find plpgsql's inline handler OID */
    lang_tup = SearchSysCache1(LANGNAME, CStringGetDatum("plpgsql"));
    if (!HeapTupleIsValid(lang_tup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("plpgsql_wrap: language \"plpgsql\" not found")));

    lang_form          = (Form_pg_language) GETSTRUCT(lang_tup);
    plpgsql_inline_oid = lang_form->laninline;
    ReleaseSysCache(lang_tup);

    if (!OidIsValid(plpgsql_inline_oid))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_OBJECT),
                 errmsg("plpgsql_wrap: plpgsql has no inline handler")));

    /* Build a copy of the InlineCodeBlock with plpgsql as the language */
    memcpy(&inner_block, codeblock, sizeof(InlineCodeBlock));
    inner_block.source_text   = source;
    inner_block.langIsTrusted = true;

    fmgr_info(plpgsql_inline_oid, &flinfo);
    InitFunctionCallInfoData(*inner_fcinfo, &flinfo, 1,
                             InvalidOid, NULL, NULL);
    inner_fcinfo->args[0].value  = PointerGetDatum(&inner_block);
    inner_fcinfo->args[0].isnull = false;

    (void) FunctionCallInvoke(inner_fcinfo);

    if (source_is_palloc)
    {
        explicit_bzero(source, strlen(source));
        pfree(source);
    }

    PG_RETURN_VOID();
}

/* ====================================================================
 * CALL HANDLER
 *
 * Called for every invocation of a plpgsql_wrap function.
 *
 * Previous versions swapped pg_proc.prosrc/prolang on disk around every
 * call.  Two sessions calling the same function then updated the same
 * catalog row and failed with "tuple concurrently updated" (issue #2);
 * it also bloated pg_proc, forced a plpgsql recompilation on every call,
 * wrote the plain source to the WAL and could not work on a standby.
 *
 * Execution flow (see compile_with_plain_source()):
 *   1. Decrypt the wrapped prosrc in memory.
 *   2. Let plpgsql_compile() see the plain source through a temporary,
 *      backend-local substitution of the pinned syscache entry.
 *   3. Restore the syscache entry and wipe the plain copy.
 *   4. Invoke plpgsql_call_handler() via fmgr; it finds its compiled
 *      function still valid and executes it.
 *
 * Per-call-site cache (fn_extra / WrapCacheEntry):
 *   Stores the plpgsql handler/compiler entry points and a persistent
 *   FmgrInfo whose fn_extra holds plpgsql's compiled function.
 * ==================================================================== */
/*
 * compile_with_plain_source
 *
 * Make plpgsql compile (or re-validate its cached copy of) the function
 * without ever writing the decrypted source to pg_proc.
 *
 * plpgsql_compile() fetches the function's pg_proc tuple through the
 * PROCOID syscache.  We pin that very syscache entry, and for the duration
 * of the plpgsql_compile() call only we point its t_data at an in-memory
 * copy of the tuple whose prosrc is the plain source.  The copy keeps the
 * original tuple header (xmin, ctid, xact infomask bits) and t_self is not
 * touched, so the PLpgSQL_function cache entry produced is keyed on the
 * real catalog row and stays valid for later calls.  The original t_data
 * is restored before returning, and the plain copy is wiped.
 *
 * Nothing is written to disk or WAL, nothing is visible to other backends,
 * and no user code runs while the swap is in effect (compilation only), so
 * recursive calls and calls from inside the body always see the wrapped
 * prosrc.
 *
 * Between our own SearchSysCache1() and plpgsql's we do not take any lock,
 * so no invalidation message can be processed there and plpgsql gets the
 * same (pinned) entry.
 */
static void
compile_with_plain_source(WrapCacheEntry *cache, FunctionCallInfo plfcinfo)
{
    Oid           fn_oid = cache->fn_oid;
    Relation      rel;
    TupleDesc     desc;
    HeapTuple     procTup;
    HeapTuple     plainTup;
    HeapTupleHeader saved_data;
    uint32        saved_len;
    bool          attr_isnull;
    Datum         prosrc_datum;
    char         *prosrc;
    char         *plain_src;
    Datum         values[Natts_pg_proc];
    bool          nulls[Natts_pg_proc];
    bool          replaces[Natts_pg_proc];

    /*
     * Open pg_proc first: lock acquisition may process invalidations, which
     * must not happen once the syscache entry has been swapped.
     */
    rel  = table_open(ProcedureRelationId, AccessShareLock);
    desc = RelationGetDescr(rel);

    procTup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(procTup))
        elog(ERROR, "plpgsql_wrap: pg_proc lookup failed for %u", fn_oid);

    prosrc_datum = SysCacheGetAttr(PROCOID, procTup,
                                   Anum_pg_proc_prosrc, &attr_isnull);
    if (attr_isnull)
        elog(ERROR, "plpgsql_wrap: prosrc is NULL for %u", fn_oid);
    prosrc = TextDatumGetCString(prosrc_datum);

    /* ---- Decrypt ------------------------------------------------ */
    {
        int      blen;
        uint8_t *blob = prosrc_to_blob(prosrc, &blen);

        if (blob == NULL)
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_CORRUPTED),
                     errmsg("plpgsql_wrap: prosrc for OID %u is not in "
                            "PLPGSQLWRAP format -- was this function created "
                            "with LANGUAGE plpgsql_wrap?", fn_oid)));
        plain_src = aes_decrypt(blob, blen);
        pfree(blob);
        pfree(prosrc);
    }

    /* ---- Build an in-memory copy of the row with the plain source */
    memset(values,   0, sizeof(values));
    memset(nulls,    false, sizeof(nulls));
    memset(replaces, false, sizeof(replaces));
    values[Anum_pg_proc_prosrc - 1]   = CStringGetTextDatum(plain_src);
    replaces[Anum_pg_proc_prosrc - 1] = true;

    plainTup = heap_modify_tuple(procTup, desc, values, nulls, replaces);
    explicit_bzero(plain_src, strlen(plain_src));
    pfree(plain_src);

    /* Keep the identity plpgsql uses to validate its cache (xmin, ctid) */
    plainTup->t_data->t_choice = procTup->t_data->t_choice;
    plainTup->t_data->t_ctid   = procTup->t_data->t_ctid;
    plainTup->t_data->t_infomask =
        (plainTup->t_data->t_infomask & ~HEAP_XACT_MASK) |
        (procTup->t_data->t_infomask & HEAP_XACT_MASK);

    /* ---- Swap, compile, restore --------------------------------- */
    saved_data = procTup->t_data;
    saved_len  = procTup->t_len;
    procTup->t_data = plainTup->t_data;
    procTup->t_len  = plainTup->t_len;

    PG_TRY();
    {
        (void) cache->plpgsql_compile(plfcinfo, false);
    }
    PG_CATCH();
    {
        procTup->t_data = saved_data;
        procTup->t_len  = saved_len;
        explicit_bzero(plainTup->t_data, plainTup->t_len);
        PG_RE_THROW();
    }
    PG_END_TRY();

    procTup->t_data = saved_data;
    procTup->t_len  = saved_len;
    explicit_bzero(plainTup->t_data, plainTup->t_len);
    heap_freetuple(plainTup);

    ReleaseSysCache(procTup);
    table_close(rel, AccessShareLock);
}

PG_FUNCTION_INFO_V1(pgwrap_call_handler);
Datum
pgwrap_call_handler(PG_FUNCTION_ARGS)
{
    Oid              fn_oid = fcinfo->flinfo->fn_oid;
    WrapCacheEntry  *cache;
    Datum            result;
    FunctionCallInfo plpgsql_fcinfo;

    /* ---- Per-call-site cache: resolve handlers once ------------- */
    if (fcinfo->flinfo->fn_extra == NULL)
    {
        HeapTuple        lang_tup;
        Form_pg_language lf;
        MemoryContext    oldcxt;

        cache = (WrapCacheEntry *)
            MemoryContextAllocZero(fcinfo->flinfo->fn_mcxt,
                                   sizeof(WrapCacheEntry));
        cache->fn_oid = fn_oid;

        /* Resolve plpgsql language OID and its call handler OID */
        lang_tup = SearchSysCache1(LANGNAME, CStringGetDatum("plpgsql"));
        if (!HeapTupleIsValid(lang_tup))
            ereport(ERROR,
                    (errcode(ERRCODE_UNDEFINED_OBJECT),
                     errmsg("plpgsql_wrap: language \"plpgsql\" not found")));
        lf = (Form_pg_language) GETSTRUCT(lang_tup);
        cache->plpgsql_lang_oid = lf->oid;
        cache->plpgsql_call_oid = lf->lanplcallfoid;
        ReleaseSysCache(lang_tup);

        if (!OidIsValid(cache->plpgsql_call_oid))
            ereport(ERROR,
                    (errcode(ERRCODE_UNDEFINED_OBJECT),
                     errmsg("plpgsql_wrap: plpgsql has no call handler")));

        /* plpgsql's exported compiler entry point (also loads plpgsql) */
        cache->plpgsql_compile = (plpgsql_compile_fn)
            load_external_function("$libdir/plpgsql", "plpgsql_compile",
                                   true, NULL);

        /*
         * Persistent FmgrInfo for plpgsql: a copy of ours (fn_oid, nargs,
         * strict, retset, fn_expr for polymorphic resolution...) with
         * plpgsql_call_handler as the entry point.  Its fn_extra keeps
         * plpgsql's compiled function across calls from this call site.
         */
        oldcxt = MemoryContextSwitchTo(fcinfo->flinfo->fn_mcxt);
        {
            FmgrInfo handler;

            fmgr_info(cache->plpgsql_call_oid, &handler);
            cache->plpgsql_flinfo          = *fcinfo->flinfo;
            cache->plpgsql_flinfo.fn_addr  = handler.fn_addr;
            cache->plpgsql_flinfo.fn_extra = NULL;
        }
        MemoryContextSwitchTo(oldcxt);

        fcinfo->flinfo->fn_extra = cache;
    }
    else
    {
        cache = (WrapCacheEntry *) fcinfo->flinfo->fn_extra;
    }

    /* fn_expr may be (re)attached by the executor; keep it in sync */
    cache->plpgsql_flinfo.fn_expr = fcinfo->flinfo->fn_expr;

    plpgsql_fcinfo = palloc(SizeForFunctionCallInfo(fcinfo->nargs));
    memcpy(plpgsql_fcinfo, fcinfo, SizeForFunctionCallInfo(fcinfo->nargs));
    plpgsql_fcinfo->flinfo = &cache->plpgsql_flinfo;

    /*
     * Let plpgsql compile the function from the decrypted source held in
     * memory only.  If plpgsql already has a valid compiled copy (same
     * pg_proc xmin/ctid), this is a no-op on its side.
     */
    compile_with_plain_source(cache, plpgsql_fcinfo);

    /*
     * Execute.  plpgsql_call_handler() calls plpgsql_compile() again, finds
     * the cached function still valid and does not read prosrc.
     */
    result = FunctionCallInvoke(plpgsql_fcinfo);

    /* propagate result-related fields set by plpgsql */
    fcinfo->isnull = plpgsql_fcinfo->isnull;
    if (fcinfo->isnull)
        PG_RETURN_NULL();
    return result;
}

/* ====================================================================
 * SQL FUNCTION: plpgsql_wrap.unwrap_procedure(key, schema, name, args)
 *
 * Superuser only.
 * Decrypts prosrc and rewrites pg_proc: plain source + prolang = plpgsql.
 * The function is permanently converted to normal LANGUAGE plpgsql.
 *
 * args (optional): the identity argument string, e.g. "integer, text".
 * Required when the schema+name combination is ambiguous (overloading).
 * ==================================================================== */
PG_FUNCTION_INFO_V1(pgwrap_unwrap_procedure);
Datum
pgwrap_unwrap_procedure(PG_FUNCTION_ARGS)
{
    text  *key_t    = PG_GETARG_TEXT_PP(0);
    text  *schema_t = PG_GETARG_TEXT_PP(1);
    text  *name_t   = PG_GETARG_TEXT_PP(2);

    char  *key      = text_to_cstring(key_t);
    char  *schema   = text_to_cstring(schema_t);
    char  *fname    = text_to_cstring(name_t);
    char  *args_str = NULL;

    Oid    fn_oid   = InvalidOid;
    char  *prosrc, *plain_src;
    bool   attr_isnull;
    Datum  prosrc_datum;
    int    spi_rc;
    HeapTuple tup;
    StringInfoData query;

    if (PG_NARGS() > 3 && !PG_ARGISNULL(3))
	    args_str = text_to_cstring(PG_GETARG_TEXT_PP(3));

    if (strcmp(key, WRAP_KEY_HEX) != 0)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
                 errmsg("plpgsql_wrap: wrong key to unwrap procedure")));

    if (!superuser())
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg("plpgsql_wrap: only superusers may unwrap")));

    /* ---- Resolve OID  --  handle overloaded functions ------------- */
    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "plpgsql_wrap: SPI_connect failed");
    else
        initStringInfo(&query);

    if (args_str != NULL)
    {
        /* Disambiguate by identity argument string */
	appendStringInfo(&query,
            "SELECT p.oid "
            "  FROM pg_catalog.pg_proc      p "
            "  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            " WHERE n.nspname = %s "
            "   AND p.proname = %s "
            "   AND pg_catalog.pg_get_function_identity_arguments(p.oid) = %s",
            quote_literal_cstr(schema),
            quote_literal_cstr(fname),
            quote_literal_cstr(args_str));
    }
    else
    {
	appendStringInfo(&query,
            "SELECT p.oid "
            "  FROM pg_catalog.pg_proc      p "
            "  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            " WHERE n.nspname = %s AND p.proname = %s",
            quote_literal_cstr(schema),
            quote_literal_cstr(fname));

    }

    spi_rc = SPI_execute(query.data, true, 1);

    if (spi_rc != SPI_OK_SELECT || SPI_processed == 0)
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_FUNCTION),
                 errmsg("plpgsql_wrap: function %s.%s%s%s not found",
                        schema, fname,
                        (args_str != NULL) ? "(" : "",
                        (args_str != NULL) ? args_str : "")));
    }

    if (SPI_processed > 1)
    {
        SPI_finish();
        ereport(ERROR,
                (errcode(ERRCODE_AMBIGUOUS_FUNCTION),
                 errmsg("plpgsql_wrap: function name %s.%s is ambiguous  --  "
                        "supply the argument list as the third parameter",
                        schema, fname)));
    }

    fn_oid = DatumGetObjectId(
        SPI_getbinval(SPI_tuptable->vals[0],
                      SPI_tuptable->tupdesc, 1, &attr_isnull));
    SPI_finish();

    /* ---- Read prosrc ------------------------------------------- */
    tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn_oid));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR,
                (errmsg("plpgsql_wrap: pg_proc lookup failed for %u",
                        fn_oid)));

    prosrc_datum = SysCacheGetAttr(PROCOID, tup,
                                   Anum_pg_proc_prosrc, &attr_isnull);
    if (attr_isnull)
    {
        ReleaseSysCache(tup);
        ereport(ERROR, (errmsg("plpgsql_wrap: prosrc is NULL")));
    }
    prosrc = TextDatumGetCString(prosrc_datum);
    ReleaseSysCache(tup);

    /* ---- Decode + decrypt -------------------------------------- */
    {
        int      blen;
        uint8_t *blob = prosrc_to_blob(prosrc, &blen);

        if (blob == NULL)
            ereport(ERROR,
                    (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                     errmsg("plpgsql_wrap: %s.%s is not a wrapped function",
                            schema, fname)));

        plain_src = aes_decrypt(blob, blen);
        pfree(blob);
        pfree(prosrc);
    }

    /* ---- Rewrite pg_proc: plain source + lang = plpgsql -------- */
    update_prosrc_and_lang(fn_oid, plain_src, get_plpgsql_lang_oid());
    CommandCounterIncrement();

    explicit_bzero(plain_src, strlen(plain_src));
    pfree(plain_src);

    PG_RETURN_VOID();
}

/* ====================================================================
 * SQL FUNCTION: plpgsql_wrap.verify_blob(prosrc text)
 *
 * C-backed: performs a full GCM authentication of the blob.
 * Returns TRUE  if the blob authenticates correctly with the current key.
 * Returns FALSE if the prosrc is not in wrapped format.
 * Raises  ERROR if the blob is malformed or the GCM tag check fails.
 *
 * Use after pg_dump / pg_restore to pre-validate every wrapped function
 * before going live, without waiting for the first call.
 * ==================================================================== */
PG_FUNCTION_INFO_V1(pgwrap_verify_blob);
Datum
pgwrap_verify_blob(PG_FUNCTION_ARGS)
{
    text       *prosrc_t = PG_GETARG_TEXT_PP(0);
    const char *prosrc   = text_to_cstring(prosrc_t);
    int         blen;
    uint8_t    *blob;

    blob = prosrc_to_blob(prosrc, &blen);
    if (blob == NULL)
        PG_RETURN_BOOL(false);   /* not in wrapped format */

    /* Full GCM authentication  --  raises ERROR if it fails */
    aes_authenticate_only(blob, blen);
    pfree(blob);

    PG_RETURN_BOOL(true);
}
