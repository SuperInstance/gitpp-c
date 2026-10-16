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
        char *s = malloc(len + 1);
        // Unescape
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
                        // Skip unicode escape (we don't fully support it)
                        if (i + 4 < len) {
                            i += 4;
                        }
                        break;
                    }
                    default: s[j++] = start[i]; break;
                }
            } else {
                s[j++] = start[i];
            }
        }
        s[j] = '\0';
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
                if (m->value->type == JSON_STRING) {
                    m->key = m->value->u.string;
                }
                skip_ws(p);
                if (**p == ':') (*p)++;
                m->value = json_parse_value(p);
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

// ========== Record representation ==========

typedef struct {
    char *id;
    char **parents;
    size_t parent_count;
    char *kind;
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
    r.kind = (char *)obj_get_str(obj, "kind");
    r.reason = (char *)obj_get_str(obj, "reason");
    if (!r.kind) r.kind = "task";
    
    json_value_t *parents = obj_get(obj, "parents");
    if (parents && parents->type == JSON_ARRAY) {
        r.parent_count = parents->u.array.count;
        r.parents = malloc(sizeof(char*) * r.parent_count);
        for (size_t i = 0; i < r.parent_count; i++) {
            json_value_t *p = parents->u.array.items[i];
            if (p->type == JSON_STRING) r.parents[i] = p->u.string;
            else r.parents[i] = "";
        }
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
    
    json_value_t kind_val = {0};
    kind_val.type = JSON_STRING;
    kind_val.u.string = r->kind ? r->kind : "task";
    
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
    
    // Build canon object members
    json_value_t *member_values[5];
    char *member_keys[5] = {"effects", "id", "kind", "parents", "reason"};
    member_values[0] = &eff_val;
    member_values[1] = &id_val;
    member_values[2] = &kind_val;
    member_values[3] = &parents_arr;
    member_values[4] = &reason_val;
    
    json_value_t canon = {0};
    canon.type = JSON_OBJECT;
    canon.u.object.members = (json_member_t **)member_values;  // hack: treat as members
    canon.u.object.count = 5;
    
    // We need a real emit_object_sorted, but that walks the union. Let me
    // just emit manually.
    char buf[8192];
    size_t pos = 0;
    
    // Sort the 5 keys alphabetically: effects, id, kind, parents, reason
    // (already in that order)
    
    buf[pos++] = '{';
    for (int i = 0; i < 5; i++) {
        if (i > 0) { buf[pos++] = ','; buf[pos++] = ' '; }
        // emit key
        buf[pos++] = '"';
        for (const char *p = member_keys[i]; *p; p++) buf[pos++] = *p;
        buf[pos++] = '"';
        buf[pos++] = ':';
        buf[pos++] = ' ';
        // emit value
        // ... we'd need a full emit_value that takes FILE*
        // For now, just append the value (as a JSON snippet)
        // We need to use the actual emit_value
        break;
    }
    
    // OK this approach is getting too complex. Let me use the existing 
    // emit_value via FILE*.
    // Reset and do it properly
    memset(buf, 0, sizeof(buf));
    FILE *mem = fmemopen(buf, sizeof(buf), "w");
    
    // Manually emit sorted object: keys are already in sort order
    fputc('{', mem);
    for (int i = 0; i < 5; i++) {
        if (i > 0) fputs(", ", mem);
        // emit key
        emit_string(mem, member_keys[i]);
        fputs(": ", mem);
        // emit value
        emit_value(mem, member_values[i]);
    }
    fputc('}', mem);
    fclose(mem);
    
    // Get the length actually written
    pos = strlen(buf);
    
    // Hash
    uint8_t hash[32];
    sha256((unsigned char *)buf, pos, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = '\0';
    
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

/* DFS colouring. Returns 1 when `rid` is already on the current path. */
static int cycle_dfs(int rid, unsigned char *color, unsigned char *in_cycle) {
    if (color[rid] == 1) return 1;
    if (color[rid] == 2) return 0;
    color[rid] = 1;
    for (size_t p = 0; p < records[rid].parent_count; p++) {
        int pi = record_index(records[rid].parents[p]);
        if (pi < 0) continue;
        if (cycle_dfs(pi, color, in_cycle)) {
            in_cycle[rid] = 1;
            in_cycle[pi] = 1;
            return 1;
        }
    }
    color[rid] = 2;
    return 0;
}

/* Structural equality via canonical re-serialization, so key order in a
 * nested object is never mistaken for a value difference (§5.3). */
static int values_equal(json_value_t *a, json_value_t *b) {
    if (!a || !b) return a == b;
    if (a->type != b->type) return 0;
    char ba[4096], bb[4096];
    FILE *fa = fmemopen(ba, sizeof(ba), "w");
    FILE *fb = fmemopen(bb, sizeof(bb), "w");
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return a == b; }
    emit_value(fa, a);
    emit_value(fb, b);
    fclose(fa); fclose(fb);
    return strcmp(ba, bb) == 0;
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
    unsigned char applied[MAX_RECORDS], color[MAX_RECORDS], in_cycle[MAX_RECORDS];
    memset(color, 0, sizeof(color));
    memset(in_cycle, 0, sizeof(in_cycle));

    /* --- orphans: missing parent (spec §5.5) --- */
    for (size_t i = 0; i < n; i++) {
        applied[i] = 1;
        for (size_t p = 0; p < records[i].parent_count; p++)
            if (record_index(records[i].parents[p]) < 0) { applied[i] = 0; break; }
    }
    /* --- cycles: excluded AND reported (spec §5.4/§5.5) --- */
    for (size_t i = 0; i < n; i++)
        if (color[i] == 0) cycle_dfs((int)i, color, in_cycle);
    for (size_t i = 0; i < n; i++) if (in_cycle[i]) applied[i] = 0;

    /* eligible[] is stable: "not an orphan, not in a cycle". Kahn mutates a
     * separate copy, because ancestry checks in §5.2 need the ORIGINAL
     * membership to stay intact for the whole resolution. */
    unsigned char eligible[MAX_RECORDS];
    for (size_t i = 0; i < n; i++) eligible[i] = applied[i];

    /* --- Kahn order, smallest id first (spec §5.4) --- */
    int in_deg[MAX_RECORDS];
    int order[MAX_RECORDS];
    size_t order_count = 0;
    for (size_t i = 0; i < n; i++) in_deg[i] = 0;
    for (size_t i = 0; i < n; i++) {
        if (!eligible[i]) continue;
        for (size_t p = 0; p < records[i].parent_count; p++) {
            int pi = record_index(records[i].parents[p]);
            if (pi >= 0 && applied[pi]) in_deg[i]++;
        }
    }
    unsigned char emitted[MAX_RECORDS];
    memset(emitted, 0, sizeof(emitted));
    while (1) {
        int pick = -1;
        for (size_t i = 0; i < n; i++) {
            if (!eligible[i] || emitted[i] || in_deg[i] != 0) continue;
            if (pick < 0 || code_point_cmp(records[i].id, records[pick].id) < 0) pick = (int)i;
        }
        if (pick < 0) break;
        order[order_count++] = pick;
        emitted[pick] = 1;
        for (size_t j = 0; j < n; j++) {
            if (j == (size_t)pick || !eligible[j] || emitted[j]) continue;
            for (size_t p = 0; p < records[j].parent_count; p++)
                if (record_index(records[j].parents[p]) == pick) { in_deg[j]--; break; }
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
    fputs("],\"orphans\":[", out);
    int first_orphan = 1;
    for (size_t i = 0; i < n; i++) {
        if (eligible[i]) continue;
        if (!first_orphan) fputc(',', out);
        first_orphan = 0;
        emit_string(out, records[i].id);
    }
    fputs("]}\n", out);

    for (size_t c = 0; c < g_conflict_count; c++) free(g_conflicts[c].losers);
    free(g_conflicts); g_conflicts = NULL; g_conflict_count = g_conflict_cap = 0;
    free(state);
}

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
