// gitpp-c — 7th fold port in C, stdlib only.
//
// Doc-only discipline: written from git.pp-spec v0.3.0 alone, zero
// reads of the other ports. This is the most rigorous test of the
// spec because C requires manual memory management, manual SHA-256,
// and a hand-rolled JSON encoder.
//
// The pass criterion: closure root at poc-quilt-1@task-c =
// 60effe23970d8a5cc837636c44685502361288c1f00577e9addfa10cbd4fc91d

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>

// ========== SHA-256 (from RFC 6234) ==========

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t block[64];
    size_t i = 0;
    while (len - i >= 64) {
        sha256_transform(state, data + i);
        i += 64;
    }
    size_t remaining = len - i;
    memcpy(block, data + i, remaining);
    block[remaining] = 0x80;
    if (remaining >= 56) {
        memset(block + remaining + 1, 0, 64 - remaining - 1);
        sha256_transform(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + remaining + 1, 0, 56 - remaining - 1);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int j = 0; j < 8; j++) {
        block[56 + j] = bits >> (56 - j*8);
    }
    sha256_transform(state, block);
    for (int j = 0; j < 8; j++) {
        out[j*4] = state[j] >> 24;
        out[j*4+1] = state[j] >> 16;
        out[j*4+2] = state[j] >> 8;
        out[j*4+3] = state[j];
    }
}

// ========== String utilities ==========

// Compare two strings by Unicode code point (for sorting)
int code_point_cmp(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        // Naive UTF-8: leading byte gives codepoint in 1-4 bytes
        // For now assume ASCII
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

// ========== JSON value representation ==========
// Simple tagged union: null, bool, number, string, array, object

typedef enum { JSON_NULL, JSON_BOOL, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT } json_type_t;

typedef struct json_value json_value_t;
typedef struct json_member json_member_t;

struct json_value {
    json_type_t type;
    union {
        bool boolean;
        double number;
        char *string;
        struct {
            json_value_t **items;
            size_t count;
        } array;
        struct {
            json_member_t **members;
            size_t count;
        } object;
    } u;
};

struct json_member {
    char *key;
    json_value_t *value;
};

// ========== JSON parser (minimal) ==========
// Supports: null, true, false, numbers, strings, arrays, objects

static json_value_t *json_parse(const char **p);

static void skip_ws(const char **p) {
    while (**p && isspace((unsigned char)**p)) (*p)++;
}

// ========== JSON string escapes (RFC 8259 section 7) ==========
//
// WHAT AN UNPAIRED SURROGATE DOES HERE, AND WHY. Spec section 2 pins the leaf
// as the SHA-256 of the canonical JSON form, and step 7 pins that form as
// UTF-8 bytes. An unpaired surrogate has NO UTF-8 encoding, so no leaf exists
// for a record carrying one -- there is no correct hash to land on. The three
// available substitutes are all bad: dropping it silently deletes data
// (exactly the bug this function had), U+FFFD invents a character the input
// never contained, and WTF-8/CESU-8 encodes a code point that is not one.
// Each produces a leaf that no other port can reproduce, which is a silent
// cross-port disagreement wearing the costume of a valid hash. So an unpaired
// surrogate is a HARD PARSE ERROR: the document is rejected and gitpp exits
// non-zero with a diagnostic. Rejecting is the only option that cannot be
// mistaken for agreement.
static const char *g_parse_error = NULL;

static void parse_fail(const char *msg) {
    if (!g_parse_error) g_parse_error = msg;
}

// The four hex digits of a \uXXXX escape, or 0 if any of them is not hex.
static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)p[i];
        unsigned d;
        if      (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a') + 10u;
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A') + 10u;
        else return 0;
        v = (v << 4) | d;
    }
    *out = v;
    return 1;
}

// Append one code point to out as UTF-8: 1, 2, 3 or 4 bytes. Writes no
// terminator -- \u0000 is a real code point here, not end-of-string.
static size_t utf8_put(unsigned cp, char *out) {
    if (cp < 0x80u) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800u) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        return 2;
    }
    if (cp < 0x10000u) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        return 3;
    }
    out[0] = (char)(0xF0u | (cp >> 18));
    out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
    out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[3] = (char)(0x80u | (cp & 0x3Fu));
    return 4;
}

static json_value_t *json_parse_value(const char **p) {
    skip_ws(p);
    if (**p == 'n') { 
        if (strncmp(*p, "null", 4) == 0) { *p += 4;
            json_value_t *v = malloc(sizeof(json_value_t));
            v->type = JSON_NULL;
            return v;
        }
    }
    if (**p == 't') {
        if (strncmp(*p, "true", 4) == 0) { *p += 4;
            json_value_t *v = malloc(sizeof(json_value_t));
            v->type = JSON_BOOL;
            v->u.boolean = true;
            return v;
        }
    }
    if (**p == 'f') {
        if (strncmp(*p, "false", 5) == 0) { *p += 5;
            json_value_t *v = malloc(sizeof(json_value_t));
            v->type = JSON_BOOL;
            v->u.boolean = false;
            return v;
        }
    }
    if (**p == '-' || (**p >= '0' && **p <= '9')) {
        char *end;
        double n = strtod(*p, &end);
        *p = end;
        json_value_t *v = malloc(sizeof(json_value_t));
        v->type = JSON_NUMBER;
        v->u.number = n;
        return v;
    }
    if (**p == '"') {
        (*p)++;
        const char *start = *p;
        while (**p && **p != '"') {
            if (**p == '\\') (*p)++;
            (*p)++;
        }
        size_t len = *p - start;

        // BUFFER SIZE. `len` is the raw span between the quotes with escapes
        // still counted, and the decoded string can never exceed it:
        //
        //     plain byte          1  ->  1
        //     \" \\ \/ \b \f \n \r \t   2  ->  1
        //     \uXXXX (BMP)       6  ->  1, 2 or 3
        //     \uD800-\uDBFF + \uDC00-\uDFFF
        //                         12  ->  4
        //
        // No escape EXPANDS, and the only branch that emits more than one
        // byte per loop iteration is the \u branch, which consumes at least 6
        // input bytes to emit at most 3 (or 12 to emit 4). So j <= len holds
        // at every iteration and len + 1 is exactly sufficient -- there is no
        // worst case the allocation misses. Test `escapes/sizing` pins this
        // with a 12000-byte all-escape string.
        char *s = malloc(len + 1);
        size_t j = 0;
        for (size_t i = 0; i < len; i++) {
            if (start[i] == '\\' && i + 1 < len) {
                i++;
                switch (start[i]) {
                    case 'n': s[j++] = '\n'; break;
                    case 't': s[j++] = '\t'; break;
                    case 'r': s[j++] = '\r'; break;
                    case 'b': s[j++] = '\b'; break;
                    case 'f': s[j++] = '\f'; break;
                    case '\\': s[j++] = '\\'; break;
                    case '"': s[j++] = '"'; break;
                    case '/': s[j++] = '/'; break;
                    case 'u': {
                        // \uXXXX: four hex digits -> one code point -> UTF-8.
                        // Spec section 2 step 7 requires the literal character
                        // in the canon, never an escape sequence, so the
                        // decoded bytes are what the leaf is taken over.
                        unsigned cp;
                        if (i + 4 >= len || !hex4(start + i + 1, &cp)) {
                            parse_fail("malformed \\uXXXX escape");
                            break;
                        }
                        i += 4;                    /* now at the last hex digit */
                        if (cp >= 0xD800u && cp <= 0xDBFFu) {
                            // High surrogate. Spec section 3.5 case 4 needs
                            // this: its id is U+1F680, written \uD83D\uDE80,
                            // which is 12 input bytes and one code point
                            // above U+FFFF, i.e. 4 UTF-8 bytes.
                            unsigned lo;
                            if (i + 6 >= len || start[i+1] != '\\' ||
                                start[i+2] != 'u' || !hex4(start + i + 3, &lo) ||
                                lo < 0xDC00u || lo > 0xDFFFu) {
                                parse_fail("high surrogate not followed by a low surrogate");
                                break;
                            }
                            i += 6;                /* now at ITS last hex digit */
                            cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                        } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                            parse_fail("low surrogate without a preceding high surrogate");
                            break;
                        }
                        j += utf8_put(cp, s + j);
                        break;
                    }
                    default:
                        // An unknown escape is not a character. Dropping the
                        // backslash rewrites "\q" to "q" silently, which is
                        // the same class of bug as the dropped \uXXXX, so
                        // reject it the way RFC 8259 section 7 does.
                        parse_fail("unknown string escape");
                        break;
                }
            } else {
                s[j++] = start[i];
            }
        }
        s[j] = '\0';
        if (g_parse_error) return NULL;
        if (**p == '"') (*p)++;
        json_value_t *v = malloc(sizeof(json_value_t));
        v->type = JSON_STRING;
        v->u.string = s;
        return v;
    }
    if (**p == '[') {
        (*p)++;
        json_value_t *v = malloc(sizeof(json_value_t));
        v->type = JSON_ARRAY;
        v->u.array.items = NULL;
        v->u.array.count = 0;
        skip_ws(p);
        if (**p != ']') {
            while (1) {
                v->u.array.items = realloc(v->u.array.items, sizeof(json_value_t*) * (v->u.array.count + 1));
                v->u.array.items[v->u.array.count++] = json_parse_value(p);
                if (g_parse_error) return NULL;
                skip_ws(p);
                if (**p == ',') { (*p)++; continue; }
                if (**p == ']') { (*p)++; break; }
                break; // error
            }
        } else {
            (*p)++;
        }
        return v;
    }
    if (**p == '{') {
        (*p)++;
        json_value_t *v = malloc(sizeof(json_value_t));
        v->type = JSON_OBJECT;
        v->u.object.members = NULL;
        v->u.object.count = 0;
        skip_ws(p);
        if (**p != '}') {
            while (1) {
                v->u.object.members = realloc(v->u.object.members, sizeof(json_member_t*) * (v->u.object.count + 1));
                json_member_t *m = malloc(sizeof(json_member_t));
                m->key = NULL;
                m->value = NULL;
                skip_ws(p);
                m->value = json_parse_value(p); // should be a string
                if (g_parse_error || !m->value) return NULL;
                if (m->value->type == JSON_STRING) {
                    m->key = m->value->u.string;
                }
                skip_ws(p);
                if (**p == ':') (*p)++;
                m->value = json_parse_value(p);
                if (g_parse_error || !m->value) return NULL;
                v->u.object.members[v->u.object.count++] = m;
                skip_ws(p);
                if (**p == ',') { (*p)++; continue; }
                if (**p == '}') { (*p)++; break; }
                break;
            }
        } else {
            (*p)++;
        }
        return v;
    }
    parse_fail("unexpected token");
    return NULL;
}

static json_value_t *json_parse(const char **p) {
    return json_parse_value(p);
}

// ========== JSON canonical encoder (per spec) ==========

// Number formatting per spec §3
// Try 15/16/17 sig digits (Python repr short algorithm). Integer form
// requires |v| < 1e16 to fit in int64 across all 5 ports.
// Special case: if |v| >= 1e16 and the only round-trip is integer form,
// skip it and use scientific (Python's repr() does the same).
static void emit_number(FILE *out, double v) {
    if (v == 0) { fprintf(out, "0"); return; }
    if (v == floor(v) && fabs(v) < 1e16) {
        fprintf(out, "%lld", (long long)v);
        return;
    }
    double abs_v = fabs(v);
    char buf[64];
    int digits;
    int found = 0;
    for (digits = 15; digits <= 17; digits++) {
        snprintf(buf, sizeof(buf), "%.*g", digits, v);
        double back = strtod(buf, NULL);
        if (back == v) {
            if (abs_v >= 1e16 && strchr(buf, 'e') == NULL) continue;
            found = 1;
            break;
        }
    }
    if (!found) {
        snprintf(buf, sizeof(buf), "%.16e", v);
        char *ep = strchr(buf, 'e');
        if (ep) {
            char *p = ep - 1;
            while (p > buf && *p == '0') p--;
            if (*p == '.') p--;
            memmove(p + 1, ep, strlen(ep) + 1);
        }
    }
    if (abs_v < 1e-4 || abs_v >= 1e16) {
        char *e = strchr(buf, 'e');
        if (e) {
            *e = '\0';
            e++;
            int exp = atoi(e);
            fprintf(out, "%se%c%02d", buf, exp < 0 ? '-' : '+', abs(exp));
        } else {
            fprintf(out, "%s", buf);
        }
        return;
    }
    fprintf(out, "%s", buf);
}

static void emit_string(FILE *out, const char *s) {
    fputc('"', out);
    while (*s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else fputc(c, out);
        }
        s++;
    }
    fputc('"', out);
}

// Member comparator for sorting object keys (codepoint order, ASCII ok)
static int member_cmp(const void *a, const void *b) {
    const json_member_t *ma = *(const json_member_t **)a;
    const json_member_t *mb = *(const json_member_t **)b;
    return strcmp(ma->key, mb->key);
}

static void emit_value(FILE *out, json_value_t *v);

// Get all members of an object as a sorted array
static void emit_object_sorted(FILE *out, json_value_t *v) {
    if (v->type != JSON_OBJECT) {
        fputs("null", out);
        return;
    }
    // Sort member indices
    size_t n = v->u.object.count;
    json_member_t **sorted = malloc(sizeof(json_member_t*) * n);
    for (size_t i = 0; i < n; i++) sorted[i] = v->u.object.members[i];
    qsort(sorted, n, sizeof(json_member_t*), member_cmp);
    
    fputc('{', out);
    for (size_t i = 0; i < n; i++) {
        if (i > 0) fputs(", ", out);
        emit_string(out, sorted[i]->key);
        fputs(": ", out);
        emit_value(out, sorted[i]->value);
    }
    fputc('}', out);
    free(sorted);
}

static void emit_value(FILE *out, json_value_t *v) {
    if (!v) { fputs("null", out); return; }
    if (!v) { fputs("null", out); return; }
    switch (v->type) {
        case JSON_NULL: fputs("null", out); break;
        case JSON_BOOL: fputs(v->u.boolean ? "true" : "false", out); break;
        case JSON_NUMBER: emit_number(out, v->u.number); break;
        case JSON_STRING: emit_string(out, v->u.string); break;
        case JSON_ARRAY:
            fputc('[', out);
            for (size_t i = 0; i < v->u.array.count; i++) {
                if (i > 0) fputs(", ", out);
                emit_value(out, v->u.array.items[i]);
            }
            fputc(']', out);
            break;
        case JSON_OBJECT:
            emit_object_sorted(out, v);
            break;
    }
}

// ========== Canonical-form sink ==========
//
// Every canonical string this port hashes or compares used to be built into a
// fixed stack array -- `char buf[8192]` in record_leaf(), `char ba[4096]` in
// values_equal(). A record whose canonical form exceeded that array was
// silently truncated before the bytes ever reached SHA-256, so the leaf was
// the hash of a PREFIX of the record, with no error and no warning. In
// values_equal() truncation was worse than a wrong hash: two different values
// sharing a long prefix compared EQUAL, which deleted a real §5.3 conflict from
// the fold.
//
// The fix is not a bigger array. There is no constant in this file that an
// adversarial record (a 10 MB string in `effects` is enough) cannot exceed, so
// any fixed bound -- 8 KiB, 1 MiB, 1 GiB -- is the same bug one size down.
//
// open_memstream() is the same glibc extension the port already depends on for
// fmemopen() (see the Makefile: this is why -std=gnu99, not -std=c99, is
// mandatory), and it reallocates its backing store as the emitter writes. The
// canonical form is therefore unbounded BY CONSTRUCTION: it is limited only by
// memory, and if memory runs out the failure is loud, not silent. There is no
// size to get wrong, so there is no bound to prove.
//
// A caller-owned struct is required: open_memstream() records the ADDRESSES of
// buf/len, so the canon_t must outlive the stream. canon_end() hands back the
// malloc'd buffer (NUL-terminated, per POSIX) and leaves the length in c->len.

typedef struct {
    FILE *fp;
    char *buf;
    size_t len;
} canon_t;

static void canon_begin(canon_t *c) {
    c->buf = NULL;
    c->len = 0;
    c->fp = open_memstream(&c->buf, &c->len);
    if (!c->fp) {
        fprintf(stderr, "gitpp: open_memstream failed (%s)\n", strerror(errno));
        exit(1);
    }
}

// Flush and close. Returns the malloc'd canonical bytes; caller frees.
// Never returns a short buffer: an I/O or allocation failure inside the
// memstream leaves the stream in an error state, and hashing what did land
// would be precisely the silent-wrong-answer bug this replaced.
static char *canon_end(canon_t *c) {
    if (fflush(c->fp) != 0 || ferror(c->fp)) {
        fprintf(stderr, "gitpp: canonical form write failed (%s)\n", strerror(errno));
        fclose(c->fp);
        exit(1);
    }
    if (fclose(c->fp) != 0) {
        fprintf(stderr, "gitpp: canonical form close failed (%s)\n", strerror(errno));
        free(c->buf);
        exit(1);
    }
    return c->buf;
}

// Canonical serialisation of `v` as a malloc'd NUL-terminated string.
// *out_len receives the exact length (the buffer's NUL is not counted).
static char *canon_of(json_value_t *v, size_t *out_len) {
    canon_t c;
    canon_begin(&c);
    emit_value(c.fp, v);
    char *buf = canon_end(&c);
    if (out_len) *out_len = c.len;
    return buf;
}

// ========== Record representation ==========

typedef struct {
    char *id;
    char **parents;
    size_t parent_count;
    char *kind;             // NULL when kind is absent, null, or not a string
    json_value_t *kind_raw; // the raw `kind` value, for the canon (spec §2 step 4)
    json_value_t *effects; // raw JSON object
    char *reason;
} record_t;

#define MAX_RECORDS 1024
static record_t records[MAX_RECORDS];
static size_t record_count = 0;

// Get a field from an object
static json_value_t *obj_get(json_value_t *obj, const char *key) {
    if (obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->u.object.count; i++) {
        if (strcmp(obj->u.object.members[i]->key, key) == 0) {
            return obj->u.object.members[i]->value;
        }
    }
    return NULL;
}

// Get a string field
static const char *obj_get_str(json_value_t *obj, const char *key) {
    json_value_t *v = obj_get(obj, key);
    if (!v || v->type != JSON_STRING) return NULL;
    return v->u.string;
}

// Build a record from a JSON object
static record_t parse_record(json_value_t *obj) {
    record_t r = {0};
    r.id = (char *)obj_get_str(obj, "id");
    /* kind stays NULL when it is absent, JSON null, or not a JSON string.
     *
     * Spec §1.1 defaults kind to null, and spec v0.4.6 §5.1 says a record
     * whose kind is null -- or is not one of the three names -- "has no
     * class" and "ranks lowest": it can win an uncontested key and loses
     * every contest against any classifiable record. class_rank() below
     * already returns 0 for exactly that case; all this line did was stop the
     * NULL from ever reaching it.
     *
     * `if (!r.kind) r.kind = "task";` rewrote absent, null AND non-string
     * kinds as a real task -- the MIDDLE class -- so a record with no kind
     * outranked a witness and took its key. obj_get_str returns NULL for
     * every one of those three cases, so the promotion was invisible.
     *
     * kind:"" is a JSON string, so obj_get_str returns it and class_rank("")
     * returns 0 on its own. That path was already correct and is unchanged.
     */
    r.kind = (char *)obj_get_str(obj, "kind");
    r.kind_raw = obj_get(obj, "kind");
    r.reason = (char *)obj_get_str(obj, "reason");
    
    // Spec §1.1: parents is an array of strings "Treated as a set; ordering
    // carries no meaning", and §2 step 3 takes "the SET of str(parent)". So a
    // repeated id is one parent, not two. Deduplicating here fixes it in both
    // consumers at once -- the leaf canon, which was emitting ["b","b"] where
    // the spec's canon is ["b"], and the fold's in-degree count below, which
    // counted a repeated parent twice and so never reached zero (see (B)).
    json_value_t *parents = obj_get(obj, "parents");
    if (parents && parents->type == JSON_ARRAY) {
        size_t raw = parents->u.array.count;
        char **buf = malloc(sizeof(char*) * (raw ? raw : 1));
        size_t kept = 0;
        for (size_t i = 0; i < raw; i++) {
            json_value_t *p = parents->u.array.items[i];
            const char *pid = (p && p->type == JSON_STRING) ? p->u.string : "";
            int dup = 0;
            for (size_t k = 0; k < kept; k++)
                if (strcmp(buf[k], pid) == 0) { dup = 1; break; }
            if (!dup) buf[kept++] = (char *)pid;
        }
        r.parent_count = kept;
        r.parents = buf;
    }
    r.effects = obj_get(obj, "effects");
    if (!r.effects) {
        r.effects = &(json_value_t){.type = JSON_OBJECT, .u.object = {0}};
    }
    return r;
}

// Sort parents by codepoint
static int parent_cmp(const void *a, const void *b) {
    const char *pa = *(const char **)a;
    const char *pb = *(const char **)b;
    return code_point_cmp(pa, pb);
}

// Compute the leaf hash of a record
static void record_leaf(record_t *r, char out_hex[65]) {
    // Build canon: {effects, id, kind, parents (sorted), reason}
    // Use stack-allocated values
    json_value_t eff_val = {0};
    eff_val.type = r->effects->type;
    eff_val.u = r->effects->u;  // shallow copy the union
    
    json_value_t id_val = {0};
    id_val.type = JSON_STRING;
    id_val.u.string = r->id ? r->id : "";
    
    // Spec §2 step 4: kind is emitted RAW, and null when absent. The old
    // `r->kind ? r->kind : "task"` hashed every absent/null kind as a real
    // task, so in the leaf domain a kindless record ALIASED a task record --
    // the same collision the fold saw, reached a second time.
    json_value_t kind_val = {0};
    kind_val.type = JSON_NULL;
    if (r->kind_raw) kind_val = *r->kind_raw;
    
    // Sort parents
    char **sorted_parents = NULL;
    if (r->parent_count > 0) {
        sorted_parents = malloc(sizeof(char*) * r->parent_count);
        for (size_t i = 0; i < r->parent_count; i++) sorted_parents[i] = r->parents[i];
        qsort(sorted_parents, r->parent_count, sizeof(char*), parent_cmp);
    }
    
    // Build parents array (array of json_value_t pointers)
    json_value_t parents_arr = {0};
    parents_arr.type = JSON_ARRAY;
    json_value_t **parent_items = NULL;
    if (r->parent_count > 0) {
        parent_items = malloc(sizeof(json_value_t*) * r->parent_count);
        for (size_t i = 0; i < r->parent_count; i++) {
            parent_items[i] = malloc(sizeof(json_value_t));
            parent_items[i]->type = JSON_STRING;
            parent_items[i]->u.string = sorted_parents[i];
        }
        parents_arr.u.array.items = parent_items;
        parents_arr.u.array.count = r->parent_count;
    }
    
    json_value_t reason_val = {0};
    if (r->reason) {
        reason_val.type = JSON_STRING;
        reason_val.u.string = r->reason;
    } else {
        reason_val.type = JSON_NULL;
    }
    
    // The canon object's five members. They are already in the order §2 step 1
    // pins (effects, id, kind, parents, reason), so nothing has to be sorted
    // here -- but they are still emitted through emit_string/emit_value, which
    // is what makes the nested effects map sort itself.
    json_value_t *member_values[5];
    char *member_keys[5] = {"effects", "id", "kind", "parents", "reason"};
    member_values[0] = &eff_val;
    member_values[1] = &id_val;
    member_values[2] = &kind_val;
    member_values[3] = &parents_arr;
    member_values[4] = &reason_val;

    // Emitted into a GROWABLE canonical sink (see "Canonical-form sink"
    // above). This used to be `char buf[8192]` + fmemopen(), which silently
    // hashed the first 8191 bytes of any record whose canonical form was
    // larger -- so a record with a long string in `effects` aliased every other
    // record that shared its first 8191 canonical bytes. open_memstream
    // reallocates as it writes, so there is no length at which the leaf can
    // come from a prefix of the record.
    canon_t c;
    canon_begin(&c);
    fputc('{', c.fp);
    for (int i = 0; i < 5; i++) {
        if (i > 0) fputs(", ", c.fp);
        // emit key
        emit_string(c.fp, member_keys[i]);
        fputs(": ", c.fp);
        // emit value
        emit_value(c.fp, member_values[i]);
    }
    fputc('}', c.fp);
    char *canon = canon_end(&c);

    // Hash the WHOLE canonical form. c.len is the length open_memstream
    // recorded, not a strlen() over a buffer that might have been cut short.
    uint8_t hash[32];
    sha256((const unsigned char *)canon, c.len, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
    free(canon);
    
    if (sorted_parents) free(sorted_parents);
    if (parent_items) {
        for (size_t i = 0; i < r->parent_count; i++) free(parent_items[i]);
        free(parent_items);
    }
}



// ========== Main ==========


/* ==========================================================================
 * derive() -- spec §5
 *
 * Added after gitpp-fold-conformance demonstrated that the leaf fuzz cannot
 * see fold semantics. This is the streaming model of §5.2, which is what
 * every other port uses.
 *
 *   for each record in topo order:
 *     for each key K it sets:
 *       K unset        -> this record becomes the setter
 *       higher class   -> wins; the previous setter becomes a loser
 *       equal class    -> descendant wins, else the incumbent wins
 *       lower class    -> this record is a loser
 *
 * Two spec details that are easy to get backwards. A conformance corpus
 * exists because both were shipped broken at least once:
 *
 *   1. DIRECTION (§5.2). Within the winning class a candidate is dominated
 *      if IT is an ancestor of another candidate; survivors are the
 *      most-derived. gitpp-doctor v0.2.1 asked the inverse and folded every
 *      chain to its OLDEST record.
 *   2. DISTINCTNESS (§5.3). A conflict requires 2+ DISTINCT values. Two
 *      records that agree must not produce one -- gitpp-cs v0.3.1 and
 *      gitpp-pl v0.1.4 both recorded a loser on every outranking and never
 *      compared the values.
 * ========================================================================== */

#define CLASS_OVERRIDE 3
#define CLASS_TASK     2
#define CLASS_WITNESS  1

static int class_rank(const char *kind) {
    if (!kind) return 0;
    if (strcmp(kind, "override") == 0) return CLASS_OVERRIDE;
    if (strcmp(kind, "task") == 0) return CLASS_TASK;
    if (strcmp(kind, "witness") == 0) return CLASS_WITNESS;
    return 0;
}

static int record_index(const char *id) {
    if (!id) return -1;
    for (size_t i = 0; i < record_count; i++)
        if (records[i].id && strcmp(records[i].id, id) == 0) return (int)i;
    return -1;
}

/* Is `desc` a transitive descendant of `anc` within the applied set? */
static int is_descendant(const unsigned char *applied, const char *anc, const char *desc) {
    int ai, di;
    if (!anc || !desc || strcmp(anc, desc) == 0) return 0;
    ai = record_index(anc);
    di = record_index(desc);
    if (ai < 0 || di < 0) return 0;
    unsigned char seen[MAX_RECORDS];
    int stack[MAX_RECORDS], sp = 0;
    memset(seen, 0, sizeof(seen));
    stack[sp++] = di;
    while (sp > 0) {
        int cur = stack[--sp];
        if (seen[cur]) continue;
        seen[cur] = 1;
        for (size_t p = 0; p < records[cur].parent_count; p++) {
            int pi = record_index(records[cur].parents[p]);
            if (pi < 0 || !applied[pi]) continue;
            if (strcmp(records[pi].id, anc) == 0) return 1;
            stack[sp++] = pi;
        }
    }
    return 0;
}

/* Structural equality via canonical re-serialization, so key order in a
 * nested object is never mistaken for a value difference (§5.3). */
static int values_equal(json_value_t *a, json_value_t *b) {
    if (!a || !b) return a == b;
    if (a->type != b->type) return 0;
    // Same growable sink as record_leaf(). This was `char ba[4096], bb[4096]`,
    // and it was the more dangerous of the two: a >4095-byte canonical form
    // truncated, so two DIFFERENT values with a long shared prefix compared
    // EQUAL. §5.3 then found "no genuine disagreement" and dropped a real
    // conflict out of the fold -- the ledger lost an entry, not just a hash.
    size_t la = 0, lb = 0;
    char *ba = canon_of(a, &la);
    char *bb = canon_of(b, &lb);
    int eq = (la == lb) && (memcmp(ba, bb, la) == 0);
    free(ba);
    free(bb);
    return eq;
}

typedef struct {
    char *key;
    char *winner;
    char **losers;
    size_t loser_count;
    size_t loser_cap;
} conflict_t;

static void conflict_add_loser(conflict_t *cf, const char *id) {
    for (size_t i = 0; i < cf->loser_count; i++)
        if (strcmp(cf->losers[i], id) == 0) return;
    if (cf->loser_count == cf->loser_cap) {
        cf->loser_cap = cf->loser_cap ? cf->loser_cap * 2 : 4;
        cf->losers = realloc(cf->losers, sizeof(char*) * cf->loser_cap);
    }
    cf->losers[cf->loser_count++] = (char *)id;
}

typedef struct {
    char *key;
    json_value_t *value;
    char *setter;
    int setter_class;
} state_entry_t;

// Order record INDICES by id, for the sorted `orphans` list below.
static int idx_by_id_cmp(const void *a, const void *b) {
    size_t ia = *(const size_t *)a, ib = *(const size_t *)b;
    return code_point_cmp(records[ia].id, records[ib].id);
}

// Position of each record in the §5.4 order sequence, -1 if it has none.
static int topo_pos[MAX_RECORDS];

// §5.2/§5.4: `losers` is listed in the §5.4 ORDER SEQUENCE -- the order
// `order` uses, filtered to the losers. That is NOT the order the losses were
// recorded in, and the two differ whenever a setter is DISPLACED: the
// displaced record loses at the moment the winner arrives, which is later in
// the order than any record that lost on its own turn.
//
// poc-quilt-1 is exactly that case. In the order sequence task-a is processed
// before task-b; task-b loses immediately (task-a outranks it as the
// incumbent), then override-1 arrives and displaces task-a, so task-a loses
// second. Appending on loss gives [task-b, task-a, task-d]; the order sequence
// gives [task-a, task-b, task-d], which is what the hub's golden pins.
static int loser_by_topo_cmp(const void *a, const void *b) {
    int ia = record_index(*(char *const *)a);
    int ib = record_index(*(char *const *)b);
    if (ia < 0 || ib < 0) return 0;
    return topo_pos[ia] - topo_pos[ib];
}

static conflict_t *g_conflicts = NULL;
static size_t g_conflict_count = 0, g_conflict_cap = 0;

static conflict_t *conflict_for(const char *key) {
    for (size_t i = 0; i < g_conflict_count; i++)
        if (strcmp(g_conflicts[i].key, key) == 0) return &g_conflicts[i];
    if (g_conflict_count == g_conflict_cap) {
        g_conflict_cap = g_conflict_cap ? g_conflict_cap * 2 : 8;
        g_conflicts = realloc(g_conflicts, sizeof(conflict_t) * g_conflict_cap);
    }
    memset(&g_conflicts[g_conflict_count], 0, sizeof(conflict_t));
    g_conflicts[g_conflict_count].key = (char *)key;
    return &g_conflicts[g_conflict_count++];
}

void derive(FILE *out) {
    size_t n = record_count;
    unsigned char applied[MAX_RECORDS];

    /* --- §5.5 step 1: the APPLIED set. A record whose OWN parent id does not
     *     resolve is not applied. Nothing propagates downward: §5.5 says the
     *     orphan's descendants are not auto-orphaned, and the orderability
     *     test below runs over the APPLIED set precisely so that an absent
     *     parent blocks only the record that names it. --- */
    for (size_t i = 0; i < n; i++) {
        applied[i] = 1;
        for (size_t p = 0; p < records[i].parent_count; p++)
            if (record_index(records[i].parents[p]) < 0) { applied[i] = 0; break; }
    }

    /* --- Kahn order over the APPLIED set (spec §5.4) --- */
    int in_deg[MAX_RECORDS];
    int order[MAX_RECORDS];
    size_t order_count = 0;
    for (size_t i = 0; i < n; i++) in_deg[i] = 0;
    for (size_t i = 0; i < n; i++) {
        if (!applied[i]) continue;
        for (size_t p = 0; p < records[i].parent_count; p++) {
            int pi = record_index(records[i].parents[p]);
            if (pi >= 0 && applied[pi]) in_deg[i]++;
        }
    }
    unsigned char emitted[MAX_RECORDS];
    memset(emitted, 0, sizeof(emitted));
    // §5.4 smallest-id-first, SEQUENTIAL: readiness is re-evaluated after every
    // emission, so emitting one record can release another that sorts earlier
    // than something already ready. That is the heap reading, not the tier one.
    while (1) {
        int pick = -1;
        for (size_t i = 0; i < n; i++) {
            if (!applied[i] || emitted[i] || in_deg[i] != 0) continue;
            if (pick < 0 || code_point_cmp(records[i].id, records[pick].id) < 0) pick = (int)i;
        }
        if (pick < 0) break;
        order[order_count++] = pick;
        emitted[pick] = 1;
        for (size_t j = 0; j < n; j++) {
            if (j == (size_t)pick || !applied[j] || emitted[j]) continue;
            for (size_t p = 0; p < records[j].parent_count; p++)
                if (record_index(records[j].parents[p]) == pick) { in_deg[j]--; break; }
        }
    }

    /* --- §5.4 + §5.5: what the fold runs on, and what it must REPORT.
     *
     * eligible[] is the applied set MINUS everything Kahn could not emit. It
     * used to be `applied && !in_cycle`, which is the same set for a plain
     * cycle -- but "not marked in a cycle" and "could be topologically
     * ordered" are not the same predicate. Any applied record that Kahn
     * strands is cycle-affected under §5.4 ("cycle-affected records are
     * excluded from the order") and §5.5 requires it in `orphans`, or it
     * vanishes from the result entirely -- which is the exact failure the
     * spec calls out for a port that excludes but forgets to report.
     *
     * The second clause (a parent that resolves but cannot be ordered) is
     * implied by the first and is kept only to state the rule in the spec's
     * own words: a record's in-degree counts its applied parents, so if every
     * one of them is ordered they are all emitted and the record is ordered
     * too. Dropping it and keying the report on `applied` alone is therefore
     * an equivalent mutant -- verified against the suite and 7500 fuzz cases,
     * not assumed.
     *
     * eligible[] stays stable for the whole resolution: ancestry checks in
     * §5.2 need the ORIGINAL membership, so nothing below mutates it. */
    unsigned char ordered[MAX_RECORDS], orphan[MAX_RECORDS], eligible[MAX_RECORDS];
    memset(ordered, 0, sizeof(ordered));
    memset(orphan, 0, sizeof(orphan));
    for (size_t oi = 0; oi < order_count; oi++) ordered[order[oi]] = 1;
    for (size_t i = 0; i < n; i++) topo_pos[i] = -1;
    for (size_t oi = 0; oi < order_count; oi++) topo_pos[order[oi]] = (int)oi;
    for (size_t i = 0; i < n; i++) {
        eligible[i] = (unsigned char)(applied[i] && ordered[i]);
        if (!eligible[i]) orphan[i] = 1;
        for (size_t p = 0; p < records[i].parent_count; p++) {
            int pi = record_index(records[i].parents[p]);
            if (pi >= 0 && applied[pi] && !ordered[pi]) orphan[i] = 1;
        }
    }

    /* --- streaming resolution (spec §5.2) --- */
    state_entry_t *state = NULL;
    size_t state_count = 0, state_cap = 0;
    g_conflicts = NULL; g_conflict_count = 0; g_conflict_cap = 0;

    for (size_t oi = 0; oi < order_count; oi++) {
        record_t *r = &records[order[oi]];
        if (!r->effects || r->effects->type != JSON_OBJECT) continue;
        int my_class = class_rank(r->kind);
        for (size_t m = 0; m < r->effects->u.object.count; m++) {
            json_member_t *mem = r->effects->u.object.members[m];
            const char *key = mem->key;
            json_value_t *val = mem->value;

            state_entry_t *slot = NULL;
            for (size_t s = 0; s < state_count; s++)
                if (strcmp(state[s].key, key) == 0) { slot = &state[s]; break; }

            if (!slot) {
                if (state_count == state_cap) {
                    state_cap = state_cap ? state_cap * 2 : 8;
                    state = realloc(state, sizeof(state_entry_t) * state_cap);
                }
                state[state_count].key = (char *)key;
                state[state_count].value = val;
                state[state_count].setter = r->id;
                state[state_count].setter_class = my_class;
                state_count++;
                continue;
            }

            int incumbent_class = slot->setter_class;
            if (my_class > incumbent_class) {
                conflict_t *cf = conflict_for(key);
                /* Record the displaced incumbent unconditionally. On the FIRST
                 * takeover cf->winner is still NULL, so a guarded add would
                 * silently drop it. The §5.3 pass below removes any loser whose
                 * value matches the winner's, so eager recording is safe. */
                conflict_add_loser(cf, slot->setter);
                cf->winner = r->id;
                slot->value = val; slot->setter = r->id; slot->setter_class = my_class;
            } else if (my_class == incumbent_class) {
                if (is_descendant(eligible, slot->setter, r->id)) {
                    conflict_t *cf = conflict_for(key);
                    conflict_add_loser(cf, slot->setter);
                    cf->winner = r->id;
                    slot->value = val; slot->setter = r->id;
                } else {
                    /* Incumbent holds. The conflict entry may be brand new, in
                     * which case its winner is still unset -- the incumbent IS
                     * the winner, so record it. Without this the entry looks
                     * like a conflict with no winner and gets discarded below. */
                    conflict_t *cf = conflict_for(key);
                    if (!cf->winner) cf->winner = slot->setter;
                    conflict_add_loser(cf, r->id);
                }
            } else {
                /* Lower class: the incumbent holds. Same winner fix. */
                conflict_t *cf = conflict_for(key);
                if (!cf->winner) cf->winner = slot->setter;
                conflict_add_loser(cf, r->id);
            }
        }
    }

    /* --- §5.3: drop conflicts with no genuine disagreement, and keep only
     *     losers whose value actually differs from the winner's. --- */
    size_t kept = 0;
    for (size_t c = 0; c < g_conflict_count; c++) {
        conflict_t *cf = &g_conflicts[c];
        int distinct = 0, have_winner = 0;
        json_value_t *wv = NULL;
        for (size_t i = 0; i < n; i++) {
            if (!records[i].effects || records[i].effects->type != JSON_OBJECT) continue;
            for (size_t m = 0; m < records[i].effects->u.object.count; m++) {
                json_member_t *mem = records[i].effects->u.object.members[m];
                if (strcmp(mem->key, cf->key) != 0) continue;
                if (cf->winner && strcmp(records[i].id, cf->winner) == 0) { wv = mem->value; have_winner = 1; }
            }
        }
        /* "2+ distinct values exist" is equivalent to "some candidate's value
         * differs from the winner's", given wv IS the winner's value. */
        if (have_winner) {
            for (size_t i = 0; i < n; i++) {
                if (!eligible[i]) continue;
                if (!records[i].effects || records[i].effects->type != JSON_OBJECT) continue;
                for (size_t m = 0; m < records[i].effects->u.object.count; m++) {
                    json_member_t *mem = records[i].effects->u.object.members[m];
                    if (strcmp(mem->key, cf->key) != 0) continue;
                    if (!values_equal(mem->value, wv)) distinct = 1;
                }
            }
        }
        if (!have_winner || !distinct) { free(cf->losers); continue; }
        size_t w = 0;
        for (size_t l = 0; l < cf->loser_count; l++) {
            int li = record_index(cf->losers[l]);
            if (li < 0 || !eligible[li]) continue;
            int differs = 0;
            if (records[li].effects && records[li].effects->type == JSON_OBJECT) {
                for (size_t m = 0; m < records[li].effects->u.object.count; m++) {
                    json_member_t *mem = records[li].effects->u.object.members[m];
                    if (strcmp(mem->key, cf->key) == 0 && !values_equal(mem->value, wv)) differs = 1;
                }
            }
            if (differs) cf->losers[w++] = cf->losers[l];
        }
        cf->loser_count = w;
        if (w == 0) { free(cf->losers); continue; }
        // §5.4 order sequence, not the order the losses were recorded in.
        // The filter above preserves relative order, which is the right
        // starting point for a stable sort and the wrong answer on its own.
        qsort(cf->losers, cf->loser_count, sizeof(char *), loser_by_topo_cmp);
        g_conflicts[kept++] = *cf;
    }
    g_conflict_count = kept;

    /* --- emit --- */
    fprintf(out, "{\"state\":{");
    for (size_t s = 0; s < state_count; s++) {
        if (s > 0) fputs(",", out);
        emit_string(out, state[s].key);
        fputs(":", out);
        emit_value(out, state[s].value);
    }
    /* Spec §5.6: setter for every key in state, not only contested ones. The
     * streaming loop above already tracked state[i].setter and discarded it,
     * which left a same-class nudge parented on the wrong record landing or
     * vanishing depending only on whether its own id sorted first. */
    fputs("},\"setters\":{", out);
    for (size_t s2 = 0; s2 < state_count; s2++) {
        if (s2 > 0) fputc(',', out);
        emit_string(out, state[s2].key);
        fputs(":", out);
        emit_string(out, state[s2].setter ? state[s2].setter : "");
    }
    fputs("},\"order\":[", out);
    for (size_t i = 0; i < order_count; i++) {
        if (i > 0) fputc(',', out);
        emit_string(out, records[order[i]].id);
    }
    fputs("],\"conflicts\":[", out);
    for (size_t c = 0; c < g_conflict_count; c++) {
        if (c > 0) fputc(',', out);
        fputs("{\"key\":", out);
        emit_string(out, g_conflicts[c].key);
        fputs(",\"winner\":", out);
        emit_string(out, g_conflicts[c].winner ? g_conflicts[c].winner : "");
        fputs(",\"losers\":[", out);
        for (size_t l = 0; l < g_conflicts[c].loser_count; l++) {
            if (l > 0) fputc(',', out);
            emit_string(out, g_conflicts[c].losers[l]);
        }
        fputs("]}", out);
    }
    // Sorted by id, not in record order. §5.5 pins WHICH records are orphans
    // but not the order they are written in, and the ledger's serialisation is
    // part of the contract for the same reason §5.2 states it for `losers`: a
    // consumer that hashes or diffs the result must not see different bytes for
    // identical semantics. Both reference ports sort here (the Python referee's
    // `sorted(orphan)`, the JS port's sortByCodePoint); this port emitted
    // record order, so a fuzz over 4000 random record sets disagreed on the
    // ordering in 99 of them while state, order and conflicts all agreed.
    // `order` is NOT sorted -- §5.4 defines it as the Kahn sequence.
    size_t orphan_idx[MAX_RECORDS], orphan_count = 0;
    for (size_t i = 0; i < n; i++)
        if (orphan[i]) orphan_idx[orphan_count++] = i;
    qsort(orphan_idx, orphan_count, sizeof(size_t), idx_by_id_cmp);
    fputs("],\"orphans\":[", out);
    for (size_t k = 0; k < orphan_count; k++) {
        if (k > 0) fputc(',', out);
        emit_string(out, records[orphan_idx[k]].id);
    }
    fputs("]}\n", out);

    for (size_t c = 0; c < g_conflict_count; c++) free(g_conflicts[c].losers);
    free(g_conflicts); g_conflicts = NULL; g_conflict_count = g_conflict_cap = 0;
    free(state);
}

// Defined below main(); declared here so the call site is not an implicit
// declaration (which is what -Wall has been warning about since v0.1.0).
void closure_root(const char *at, char out_hex[65], char closure_ids[][256], size_t *closure_count);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file.json> [--at <id>]\n", argv[0]);
        return 1;
    }
    const char *file = argv[1];
    const char *at = NULL;
    int do_derive = 0;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--at") == 0 && i + 1 < argc) at = argv[++i];
        if (strcmp(argv[i], "--derive") == 0) do_derive = 1;
    }
    FILE *f = fopen(file, "r");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);
    const char *p = data;
    json_value_t *records_json = json_parse(&p);
    if (g_parse_error) {
        fprintf(stderr, "%s: %s\n", file, g_parse_error);
        return 1;
    }
    if (!records_json || records_json->type != JSON_ARRAY) {
        fprintf(stderr, "expected array of records\n");
        return 1;
    }
    record_count = 0;
    for (size_t i = 0; i < records_json->u.array.count; i++) {
        json_value_t *r = records_json->u.array.items[i];
        if (r->type == JSON_OBJECT && record_count < MAX_RECORDS) {
            records[record_count++] = parse_record(r);
        }
    }
    if (do_derive) {
        derive(stdout);
    } else if (at) {
        char hex[65];
        char closure_ids[MAX_RECORDS][256];
        memset(closure_ids, 0, sizeof(closure_ids));
        size_t closure_count;
        closure_root(at, hex, closure_ids, &closure_count);
        printf("{\"closureRoot\":\"%s\"}\n", hex);
    } else {
        printf("{\"error\":\"no --at\"}\n");
    }
    return 0;
}

static int cmp_str_ptr(const void *a, const void *b) {
    const char *sa = *(const char *const *)a;
    const char *sb = *(const char *const *)b;
    return strcmp(sa, sb);
}

void closure_root(const char *at, char out_hex[65], char closure_ids[][256], size_t *closure_count) {
    record_t *at_rec = NULL;
    for (size_t i = 0; i < record_count; i++) {
        if (records[i].id && strcmp(records[i].id, at) == 0) {
            at_rec = &records[i];
            break;
        }
    }
    if (!at_rec) { out_hex[0] = '\0'; *closure_count = 0; return; }
    
    char **closure_set = malloc(sizeof(char*) * record_count);
    size_t closure_set_count = 0;
    bool *in_closure = calloc(record_count, sizeof(bool));
    
    size_t *idx_stack = malloc(sizeof(size_t) * record_count);
    size_t sp = 0;
    
    for (size_t i = 0; i < record_count; i++) {
        if (records[i].id && strcmp(records[i].id, at) == 0) {
            idx_stack[sp++] = i;
            in_closure[i] = true;
            closure_set[closure_set_count++] = records[i].id;
            break;
        }
    }
    
    while (sp > 0) {
        size_t cur = idx_stack[--sp];
        for (size_t i = 0; i < records[cur].parent_count; i++) {
            for (size_t j = 0; j < record_count; j++) {
                if (records[j].id && strcmp(records[j].id, records[cur].parents[i]) == 0) {
                    if (!in_closure[j]) {
                        in_closure[j] = true;
                        closure_set[closure_set_count++] = records[j].id;
                        idx_stack[sp++] = j;
                    }
                    break;
                }
            }
        }
    }
    
    qsort(closure_set, closure_set_count, sizeof(char*), cmp_str_ptr);
    
    size_t total_len = 0;
    char **lines = malloc(sizeof(char*) * (closure_set_count + 1));
    for (size_t i = 0; i < closure_set_count; i++) {
        char hex[65];
        for (size_t j = 0; j < record_count; j++) {
            if (records[j].id && strcmp(records[j].id, closure_set[i]) == 0) {
                record_leaf(&records[j], hex);
                break;
            }
        }
        size_t line_len = strlen(closure_set[i]) + 1 + 64;
        lines[i] = malloc(line_len + 2);
        if (i + 1 < closure_set_count) {
            snprintf(lines[i], line_len + 2, "%s:%s\n", closure_set[i], hex);
            total_len += line_len + 1;
        } else {
            snprintf(lines[i], line_len + 2, "%s:%s", closure_set[i], hex);
            total_len += line_len;
        }
    }
    
    char *concat = malloc(total_len + 1);
    size_t pos = 0;
    for (size_t i = 0; i < closure_set_count; i++) {
        size_t l = strlen(lines[i]);
        memcpy(concat + pos, lines[i], l);
        pos += l;
    }
    concat[pos] = '\0';
    
    uint8_t hash[32];
    sha256((unsigned char *)concat, pos, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
    
    *closure_count = closure_set_count;
    for (size_t i = 0; i < closure_set_count; i++) {
        strncpy(closure_ids[i], closure_set[i], 255);
        closure_ids[i][255] = '\0';
    }
    for (size_t i = 0; i < closure_set_count; i++) free(lines[i]);
    free(lines);
    free(concat);
    free(closure_set);
    free(in_closure);
    free(idx_stack);
}
