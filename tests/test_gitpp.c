// test_gitpp.c -- regression harness for gitpp-c.
//
// The port ships one file and no test suite, so this harness #includes
// gitpp.c directly. That buys two things a CLI-only test cannot have:
//   * record_leaf() is static, so a subprocess can never print a leaf. The
//     pinned cross-port leaves (git.pp-spec SPEC.md §3.5) are leaf assertions,
//     so the harness has to reach the function itself.
//   * parse_record() is static, and both defects under test live in it and in
//     the JSON string decoder it calls.
//
// Nothing is reimplemented here: every expectation is a literal transcribed
// from git.pp-spec (SPEC.md §2, §3.5, §5.1, §5.4, §5.5) or from
// SuperInstance/gitpp-cross-port/cross-port-leafs.json.
//
// Build: gcc -std=gnu99 -O2 -o test_gitpp tests/test_gitpp.c -lm
// Run:   ./test_gitpp        (exit 0 = all pass)

#define main gitpp_main_never_called
#include "../gitpp.c"
#undef main

#include <stdarg.h>

static int failures = 0, checks = 0;

static void ok(int cond, const char *fmt, ...) {
    checks++;
    va_list ap;
    va_start(ap, fmt);
    if (cond) { printf("  ok   "); vprintf(fmt, ap); printf("\n"); }
    else      { failures++; printf("  FAIL "); vprintf(fmt, ap); printf("\n"); }
    va_end(ap);
}

static void eq_str(const char *actual, const char *expected, const char *what) {
    checks++;
    if (actual && strcmp(actual, expected) == 0) {
        printf("  ok   %s = %s\n", what, actual);
    } else {
        failures++;
        printf("  FAIL %s\n         got      %s\n         expected %s\n",
               what, actual ? actual : "(null)", expected);
    }
}

static void section(const char *name) { printf("\n== %s ==\n", name); }

/* ---------------- helpers over the port's own internals ---------------- */

// Parse a document and install its records into the globals record_leaf()
// and derive() read. Mirrors main()'s loop exactly.
static json_value_t *load(const char *doc) {
    const char *p = doc;
    g_parse_error = NULL;      /* global and sticky; gitpp is one-shot, we are not */
    json_value_t *root = json_parse(&p);
    if (!root) return NULL;
    record_count = 0;
    for (size_t i = 0; i < root->u.array.count; i++) {
        json_value_t *r = root->u.array.items[i];
        if (r && r->type == JSON_OBJECT && record_count < MAX_RECORDS)
            records[record_count++] = parse_record(r);
    }
    return root;
}

// Leaf of a single-record document. Yields "" if the document will not parse.
static void leaf_of(const char *doc, char out[65]) {
    out[0] = '\0';
    json_value_t *root = load(doc);
    if (!root || record_count != 1) { out[0] = '\0'; return; }
    record_leaf(&records[0], out);
}

// Run derive() over a document and capture its output line.
static char *derive_of(const char *doc) {
    if (!load(doc)) return NULL;
    char *buf = NULL; size_t len = 0;
    FILE *mem = open_memstream(&buf, &len);
    if (!mem) return NULL;
    derive(mem);
    fclose(mem);
    return buf;
}

// Pull a top-level array member out of derive()'s output: array_of(doc, "order")
// -> "m","z","a"
static void array_of(const char *doc, const char *member, char *out, size_t out_sz) {
    out[0] = '\0';
    char *buf = derive_of(doc);
    if (!buf) return;
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":[", member);
    const char *s = strstr(buf, pat);
    if (s) {
        s += strlen(pat);                  /* just past the '[' */
        const char *q = s; int bal = 1;    /* we are INSIDE the array */
        while (*q && bal) {
            if (*q == '[') bal++;
            else if (*q == ']') bal--;
            if (bal) q++;
        }
        size_t n = (size_t)(q - s);        /* q sits on the closing ']' */
        if (n + 1 > out_sz) n = out_sz - 1;
        memcpy(out, s, n); out[n] = '\0';
    }
    free(buf);
}

// The "state" member of derive()'s output, as bytes.
// {"state":{"x":"W"},"setters":...}  ->  "x":"W"
static void state_of(const char *doc, char *out, size_t out_sz) {
    out[0] = '\0';
    char *buf = derive_of(doc);
    if (!buf) return;
    const char *s = strstr(buf, "\"state\":{");
    if (s) {
        s += strlen("\"state\":{");
        const char *q = s; int bal = 1;
        while (*q && bal) {
            if (*q == '{' || *q == '[') bal++;
            else if (*q == '}' || *q == ']') bal--;
            if (bal) q++;
        }
        size_t n = (size_t)(q - s);
        if (n + 1 > out_sz) n = out_sz - 1;
        memcpy(out, s, n); out[n] = '\0';
    }
    free(buf);
}

// Same, but sorted, for the members the spec pins as a SET rather than a
// sequence. Section 5.5 fixes WHICH records are orphans; it does not fix the
// order they are listed in, so this assertion is order-independent by design.
// One conflict entry from the ledger, by key.
static void conflict_of(const char *doc, const char *key, char *out, size_t out_sz) {
    out[0] = '\0';
    char *buf = derive_of(doc);
    if (!buf) return;
    char kb[64];
    snprintf(kb, sizeof(kb), "\"key\":\"%s\"", key);
    const char *c = strstr(buf, "\"conflicts\":[");
    while (c && (c = strchr(c, '{')) != NULL) {
        if (strncmp(c + 1, kb, strlen(kb)) == 0) {
            const char *e = strchr(c, '}');
            size_t n = e ? (size_t)(e - c + 1) : 0;
            if (n + 1 > out_sz) n = out_sz - 1;
            memcpy(out, c, n); out[n] = '\0';
            break;
        }
        c++;
    }
    free(buf);
}

static int parses(const char *doc) {
    const char *p = doc;
    g_parse_error = NULL;
    json_value_t *v = json_parse(&p);
    return v != NULL && g_parse_error == NULL;
}

/* ---------------------------------- tests --------------------------------- */

static void test_pinned_leaves(void) {
    section("SPEC §3.5 / cross-port-leafs.json -- the 4 pinned leaves");
    char h[65];

    leaf_of("[{\"id\":\"a\",\"kind\":\"task\",\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    eq_str(h, "229f56e059c1e8209d9e9c0a767ac70f02601f7abe53875069c7d55827533124",
           "case-1-minimal");

    leaf_of("[{\"id\":\"b\",\"kind\":\"task\",\"parents\":[\"a\"],\"effects\":{\"x\":{\"y\":1,\"z\":[1,2,3]}},\"reason\":null}]", h);
    eq_str(h, "64a3cd29253cbeca672be7792c981ef3192bf23de2d6c0dee3708d611c496ad9",
           "case-2-nested");

    leaf_of("[{\"id\":\"c\",\"kind\":\"witness\",\"parents\":[\"a\"],\"effects\":{\"ok\":true,\"msg\":\"ok\"},\"reason\":\"witnessed\"}]", h);
    eq_str(h, "97fd12eeb83d78a633613258d3357d84b6753861447a06525e4c54e18053f2f7",
           "case-3-boolean-string");

    leaf_of("[{\"id\":\"\xf0\x9f\x9a\x80\",\"kind\":\"task\",\"parents\":[\"c\"],\"effects\":{\"y\":1},\"reason\":null}]", h);
    eq_str(h, "83d31b8135b406d8d518733c5f28f3218d1c50ff2a5da2aca6cf698e6905e597",
           "case-4-non-bmp-id");
}

static void test_escapes(void) {
    section("DEFECT 1 -- \\uXXXX decoding (gitpp-c#1)");
    char plain[65], got[65], lit[65];

    // The collision that defines the defect.
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"ab\"},\"reason\":null}]", plain);
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"a\\u0001b\"},\"reason\":null}]", got);
    ok(strcmp(plain, got) != 0, "\"ab\" and \"a\\u0001b\" get DIFFERENT leaves");
    printf("         %s  \"ab\"\n         %s  \"a\\u0001b\"\n", plain, got);
    eq_str(plain, "1474b82cc1a8e2af3fae1a1a6b8651105da006d052b59a862e02641af7d7e158",
           "         \"ab\" vs the reference leaf");
    eq_str(got, "075605985ad19d0c953af5bad5082532872ae68b9268193ee2e44cccb7e2fb43",
           "         \"a\\u0001b\" vs the reference leaf");

    // Surrogate pair -> one code point above U+FFFF -> 4 UTF-8 bytes.
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"\\ud83d\\ude80\"},\"reason\":null}]", got);
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"\xf0\x9f\x9a\x80\"},\"reason\":null}]", lit);
    eq_str(got, lit, "\\uD83D\\uDE80 decodes to the literal 4-byte emoji");
    eq_str(lit, "2a098a33b77d8b43afd8ff76d4b57412a768c2972830e317271d94576e2c3d99",
           "         ... and matches the reference leaf");

    // The three BMP UTF-8 widths, plus the ASCII boundary.
    struct { const char *esc; const char *literal; const char *ref; const char *what; } u[] = {
        {"\\u007e", "~",          "916d243ecce28a0b3c42c8c013c170351d0338c961530b4e17952ac0c5472bb3", "\\u007e is 1 UTF-8 byte"},
        {"\\u00e9", "\xc3\xa9",   "484a75110e3a1284394cf4c69d809d0b46fa99a19674e7ee173053ffbf9707a3", "\\u00e9 is 2 UTF-8 bytes"},
        {"\\u20ac", "\xe2\x82\xac","d54401460933ad9959e4b0871108cd76c5d0000e4fd507d81416a8dc4b457ba8", "\\u20AC is 3 UTF-8 bytes"},
    };
    char doc[256];
    for (size_t i = 0; i < sizeof(u)/sizeof(u[0]); i++) {
        snprintf(doc, sizeof(doc),
                 "[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"%s\"},\"reason\":null}]",
                 u[i].esc);
        leaf_of(doc, got);
        eq_str(got, u[i].ref, u[i].what);
        // ... and equals the same document written with the literal character.
        snprintf(doc, sizeof(doc),
                 "[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"%s\"},\"reason\":null}]",
                 u[i].literal);
        leaf_of(doc, lit);
        eq_str(got, lit, "         ... and equals the literal-character form");
    }

    // \\u0000 must not truncate: a NUL inside a JSON string is a real code
    // point, and the decoder stores strings as NUL-terminated C strings, so
    // the fix has to keep it from silently ending the value.
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"\\u0000X\",\"k\":\"tail\"},\"reason\":null}]", got);
    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"X\",\"k\":\"tail\"},\"reason\":null}]", lit);
    ok(strcmp(got, lit) != 0, "\\u0000 is decoded, not treated as end-of-string");

    section("DEFECT 1 -- buffer sizing");
    {
        // 2000 x "\u0041" = 12000 source bytes -> 2000 output bytes, and the
        // record pads past the 8 KiB canon buffer so a truncation bug shows up
        // in the leaf rather than crashing.
        size_t n = 2000;
        char *doc = malloc(n * 6 + 8192), *w = doc;
        w += sprintf(w, "[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"");
        for (size_t i = 0; i < n; i++) w += sprintf(w, "\\u0041");
        w += sprintf(w, "\",\"pad\":\"");
        for (size_t i = 0; i < 4000; i++) *w++ = 'z';
        w += sprintf(w, "\"},\"reason\":null}]");
        *w = '\0';
        load(doc);
        record_leaf(&records[0], got);

        const char *pre = "[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"c\":\"";
        size_t plen = strlen(pre);
        char *d2 = malloc(plen + n + 8192);
        memcpy(d2, pre, plen);
        memset(d2 + plen, 'A', n);
        memcpy(d2 + plen + n, "\",\"pad\":\"", 9);
        memset(d2 + plen + n + 9, 'z', 4000);
        strcpy(d2 + plen + n + 9 + 4000, "\"},\"reason\":null}]");
        leaf_of(d2, lit);
        eq_str(got, lit, "2000 x \\u0041 == 2000 literal 'A' (no overflow, no truncation)");
        free(doc); free(d2);
    }

    section("DEFECT 1 -- malformed escapes are rejected, not silently mangled");
    ok(!parses("[\"\\ud800\"]"),        "lone high surrogate \\uD800 rejected");
    ok(!parses("[\"\\udc00\"]"),        "lone low surrogate \\uDC00 rejected");
    ok(!parses("[\"\\ud800\\u0041\"]"), "high surrogate not followed by a low one rejected");
    ok(!parses("[\"\\ud83dx\"]"),       "truncated surrogate pair rejected");
    ok(!parses("[\"\\u00zz\"]"),        "non-hex \\uXXXX rejected");
    ok(!parses("[\"\\u12\"]"),          "short \\uXXXX rejected");
    ok(!parses("[\"\\q\"]"),            "unknown escape rejected");
    ok(parses("[\"\\ud83d\\ude80\"]"),  "valid surrogate pair accepted");
    ok(parses("[\"\\udbff\\udfff\"]"),  "top of the surrogate range accepted");
    ok(parses("[\"\\ud800\\udc00\"]"),  "bottom of the surrogate range accepted");
    ok(parses("[\"\\u0041\"]"),         "plain \\uXXXX accepted");
}

static void test_kind(void) {
    section("DEFECT 2 -- absent / null / unrecognised kind (gitpp-c#2)");
    char st[8192], h[65];

    // The override from the bug report: a kindless record must not outrank a
    // witness. Spec §5.1: an unclassifiable record ranks lowest.
    state_of("[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
             "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":\"OMITTED\"},\"reason\":null}]", st, sizeof(st));
    eq_str(st, "\"x\":\"W\"", "omitted kind loses to a witness");

    const char *variants[] = {
        "[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"b\",\"kind\":null,\"parents\":[\"a\"],\"effects\":{\"x\":\"N\"},\"reason\":null}]",
        "[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"b\",\"kind\":\"\",\"parents\":[\"a\"],\"effects\":{\"x\":\"E\"},\"reason\":null}]",
        "[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"b\",\"kind\":\"banana\",\"parents\":[\"a\"],\"effects\":{\"x\":\"B\"},\"reason\":null}]",
        "[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"z\",\"parents\":[],\"effects\":{\"x\":\"Z\"},\"reason\":null}]",
        "[{\"id\":\"a\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"b\",\"kind\":\"task\",\"parents\":[\"a\"],\"effects\":{\"x\":\"T\"},\"reason\":null}]",
        "[{\"id\":\"a\",\"kind\":\"override\",\"parents\":[],\"effects\":{\"x\":\"W\"},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":\"O\"},\"reason\":null}]",
    };
    const char *want[] = {"\"x\":\"W\"", "\"x\":\"W\"", "\"x\":\"W\"", "\"x\":\"W\"",
                          "\"x\":\"T\"", "\"x\":\"W\""};
    const char *what[] = {"kind:null loses to a witness",
                          "kind:\"\" loses to a witness (it is a STRING, so it does reach class_rank)",
                          "kind:\"banana\" loses to a witness",
                          "a kindless record loses to a witness even when unrelated",
                          "kind:\"task\" still outranks a witness",
                          "kind:\"override\" still outranks a witness"};
    for (size_t i = 0; i < sizeof(variants)/sizeof(variants[0]); i++) {
        state_of(variants[i], st, sizeof(st));
        eq_str(st, want[i], what[i]);
    }

    // The other half of §5.1: "it can win an uncontested key".
    state_of("[{\"id\":\"a\",\"parents\":[],\"effects\":{\"only\":\"MINE\"},\"reason\":null}]", st, sizeof(st));
    eq_str(st, "\"only\":\"MINE\"", "a kindless record still wins an uncontested key");

    // Spec v0.4.6 §5.1: two unclassifiable records are ONE class, so the tie
    // goes to §5.2 step 3 -- ancestry first, then §5.4 topo order.
    state_of("[{\"id\":\"a\",\"parents\":[],\"effects\":{\"x\":\"ROOT\"},\"reason\":null},"
             "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":\"CHILD\"},\"reason\":null}]", st, sizeof(st));
    eq_str(st, "\"x\":\"CHILD\"", "two kindless records: the descendant wins");
    state_of("[{\"id\":\"a\",\"parents\":[],\"effects\":{\"x\":\"ROOT\"},\"reason\":null},"
             "{\"id\":\"b\",\"parents\":[],\"effects\":{\"x\":\"SIB\"},\"reason\":null}]", st, sizeof(st));
    eq_str(st, "\"x\":\"ROOT\"", "two unrelated kindless records: first in topo order wins");

    // Spec §2 step 4: kind is emitted RAW, null when absent -- not "task".
    leaf_of("[{\"id\":\"r\",\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    eq_str(h, "d29d2a1cadba06fffc5698b945c2103ea51a97f8d1f28d2f39929bbb460f6f8d",
           "absent kind canonicalises as kind:null");
    leaf_of("[{\"id\":\"r\",\"kind\":null,\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    eq_str(h, "d29d2a1cadba06fffc5698b945c2103ea51a97f8d1f28d2f39929bbb460f6f8d",
           "kind:null canonicalises as kind:null");
    leaf_of("[{\"id\":\"r\",\"kind\":\"\",\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    eq_str(h, "ade85fc49cde6b5cd6c727b4a5ee0426dc82db52e2d7240a5824b7f78179a88d",
           "kind:\"\" canonicalises as kind:\"\"");
    leaf_of("[{\"id\":\"r\",\"kind\":\"banana\",\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    eq_str(h, "ae99850300980da4f6e76fbc6e716263e9fc5382f61fa6db950df5eaf1f3dda5",
           "an unrecognised kind is kept raw in the canon");

    leaf_of("[{\"id\":\"r\",\"kind\":\"task\",\"parents\":[],\"effects\":{},\"reason\":null}]", h);
    ok(strcmp(h, "d29d2a1cadba06fffc5698b945c2103ea51a97f8d1f28d2f39929bbb460f6f8d") != 0,
       "an absent kind no longer aliases kind:\"task\"");
}

static void test_parents_set(void) {
    section("SPEC §1.1/§2 step 3 -- parents is a SET");
    char dup[65], one[65];
    leaf_of("[{\"id\":\"a\",\"kind\":\"task\",\"parents\":[\"b\",\"b\"],\"effects\":{},\"reason\":null}]", dup);
    leaf_of("[{\"id\":\"a\",\"kind\":\"task\",\"parents\":[\"b\"],\"effects\":{},\"reason\":null}]", one);
    eq_str(dup, one, "a repeated parent id does not change the leaf");
    eq_str(one, "faba8282c492036cf8f94b71fa6f37208ecbc145d24f65f443625cf6866fa648",
           "         ... and matches the reference leaf for the set {b}");
}

static void test_losers_order(void) {
    section("SPEC §5.4 -- losers are listed in the order sequence");
    char cf[1024], ord[1024];
    // The spec's own minimal witness: order is [m,z,a] and the winner is m, so
    // the order sequence gives losers [z,a] while codepoint sort gives [a,z].
    const char *doc =
        "[{\"id\":\"m\",\"kind\":\"override\",\"parents\":[],\"effects\":{\"x\":2},\"reason\":null},"
        "{\"id\":\"z\",\"kind\":\"witness\",\"parents\":[],\"effects\":{\"x\":3},\"reason\":null},"
        "{\"id\":\"a\",\"kind\":\"override\",\"parents\":[\"z\"],\"effects\":{\"x\":1},\"reason\":null}]";
    array_of(doc, "order", ord, sizeof(ord));
    eq_str(ord, "\"m\",\"z\",\"a\"", "order sequence");
    conflict_of(doc, "x", cf, sizeof(cf));
    eq_str(cf, "{\"key\":\"x\",\"winner\":\"m\",\"losers\":[\"z\",\"a\"]}",
           "losers are [z,a] -- order sequence, not codepoint");
}

// Split a comma-separated, optionally quoted list into plain tokens.
static int split_list(const char *csv, char toks[][256], int max) {
    int n = 0;
    for (const char *p = csv; *p && n < max; ) {
        while (*p == ',' || *p == ' ') p++;
        if (*p == '"') p++;
        const char *e = strchr(p, '"');
        if (!e) e = p + strlen(p);
        size_t l = (size_t)(e - p);
        if (l > 255) l = 255;
        memcpy(toks[n], p, l); toks[n][l] = '\0'; n++;
        p = (*e == '"') ? e + 1 : e;
    }
    return n;
}

// The §5.5 partition invariant: every id in the record set appears in EXACTLY
// ONE of `order` and `orphans`. Records that are applied but cannot be
// topologically ordered used to be in NEITHER -- the failure mode §5.5 calls
// out by name ("makes the records vanish from the result entirely").
static void check_partition(const char *doc, const char *what) {
    char ord[4096], orp[4096];
    array_of(doc, "order", ord, sizeof(ord));
    array_of(doc, "orphans", orp, sizeof(orp));
    char otok[64][256], ptok[64][256];
    int no = split_list(ord, otok, 64), np = split_list(orp, ptok, 64);

    load(doc);
    for (size_t i = 0; i < record_count; i++) {
        const char *id = records[i].id;
        int hits = 0;
        for (int k = 0; k < no; k++) if (strcmp(otok[k], id) == 0) hits++;
        for (int k = 0; k < np; k++) if (strcmp(ptok[k], id) == 0) hits++;
        ok(hits == 1, "%s: '%s' appears exactly once across order+orphans", what, id);
    }
    load(doc);   // leave the globals as array_of found them
}

static void test_orphans(void) {
    section("SPEC §5.5 -- orphans, including cycle descendants");
    char orp[4096], ord[4096], st[4096];

    // A 2-cycle plus a child of one of its members. The child cannot be
    // topologically ordered, so it must be REPORTED, not vanish.
    const char *cyc =
        "[{\"id\":\"a\",\"parents\":[\"b\"],\"effects\":{\"x\":1},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":2},\"reason\":null},"
        "{\"id\":\"c\",\"parents\":[\"a\"],\"effects\":{\"x\":3},\"reason\":null}]";
    array_of(cyc, "orphans", orp, sizeof(orp));
    eq_str(orp, "\"a\",\"b\",\"c\"", "2-cycle: the members AND the descendant are orphans");
    array_of(cyc, "order", ord, sizeof(ord));
    eq_str(ord, "", "2-cycle: nothing enters the fold");

    // A record that merely LEADS INTO a cycle is on no cycle itself, but it
    // still cannot be ordered, so it is still an orphan.
    const char *tail =
        "[{\"id\":\"a\",\"parents\":[\"b\"],\"effects\":{\"x\":1},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":2},\"reason\":null},"
        "{\"id\":\"d\",\"parents\":[\"c\"],\"effects\":{\"x\":4},\"reason\":null},"
        "{\"id\":\"c\",\"parents\":[\"a\"],\"effects\":{\"x\":3},\"reason\":null}]";
    array_of(tail, "orphans", orp, sizeof(orp));
    eq_str(orp, "\"a\",\"b\",\"c\",\"d\"", "a record descending from a cycle is an orphan");

    // An unrelated root is not swept up, and still folds.
    const char *root =
        "[{\"id\":\"r\",\"parents\":[],\"effects\":{\"y\":9},\"reason\":null},"
        "{\"id\":\"a\",\"parents\":[\"b\"],\"effects\":{\"x\":1},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":2},\"reason\":null}]";
    array_of(root, "orphans", orp, sizeof(orp));
    eq_str(orp, "\"a\",\"b\"", "an unrelated root is not an orphan");
    array_of(root, "order", ord, sizeof(ord));
    eq_str(ord, "\"r\"", "and it still enters the fold");

    // §5.5: an orphan's descendants are NOT auto-orphaned. Orderability is
    // computed over the applied set, so an absent parent blocks only itself.
    const char *orphan =
        "[{\"id\":\"a\",\"parents\":[\"ghost\"],\"effects\":{\"x\":1},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"a\"],\"effects\":{\"x\":2},\"reason\":null}]";
    array_of(orphan, "orphans", orp, sizeof(orp));
    eq_str(orp, "\"a\"", "only the record with the missing parent is an orphan");
    array_of(orphan, "order", ord, sizeof(ord));
    eq_str(ord, "\"b\"", "the orphan's descendant still enters the fold");

    // Orphans are listed sorted by id, not in record order: both reference
    // ports sort, and a ledger's serialisation is part of the contract for the
    // same reason §5.2 states it for `losers`. `order` is NOT sorted -- §5.4
    // defines it as the Kahn sequence.
    array_of("[{\"id\":\"zz\",\"parents\":[\"ghost\"],\"effects\":{},\"reason\":null},"
             "{\"id\":\"aa\",\"parents\":[\"ghost\"],\"effects\":{},\"reason\":null}]",
             "orphans", orp, sizeof(orp));
    eq_str(orp, "\"aa\",\"zz\"", "orphans are sorted by id, not in record order");

    section("SPEC §5.5 -- no record may vanish from the result");
    // A repeated parent id is one parent (§1.1), so the in-degree cannot be
    // stranded by counting it twice. This exact set used to fold nothing and
    // orphan nothing: b0 alone appeared, and a1 and e3 were dropped outright.
    const char *stranded =
        "[{\"id\":\"b0\",\"parents\":[],\"effects\":{\"x\":1},\"reason\":null},"
        "{\"id\":\"a1\",\"parents\":[\"b0\",\"b0\"],\"effects\":{\"y\":\"A\"},\"reason\":null},"
        "{\"id\":\"e3\",\"parents\":[\"b0\",\"a1\"],\"effects\":{\"z\":1},\"reason\":null}]";
    state_of(stranded, st, sizeof(st));
    eq_str(st, "\"x\":1,\"y\":\"A\",\"z\":1", "a repeated parent id does not strand the record");
    array_of(stranded, "order", ord, sizeof(ord));
    eq_str(ord, "\"b0\",\"a1\",\"e3\"", "repeated parents still reach the order");

    const char *tricky[] = {
        stranded, cyc, tail, root, orphan,
        "[{\"id\":\"s\",\"parents\":[\"s\"],\"effects\":{\"x\":1},\"reason\":null}]",
        "[{\"id\":\"a\",\"parents\":[\"b\"],\"effects\":{},\"reason\":null},"
        "{\"id\":\"b\",\"parents\":[\"c\"],\"effects\":{},\"reason\":null},"
        "{\"id\":\"c\",\"parents\":[\"a\"],\"effects\":{},\"reason\":null}]",
        "[{\"id\":\"x\",\"parents\":[\"ghost\"],\"effects\":{},\"reason\":null},"
        "{\"id\":\"y\",\"parents\":[\"x\"],\"effects\":{},\"reason\":null},"
        "{\"id\":\"z\",\"parents\":[\"y\"],\"effects\":{},\"reason\":null}]",
        "[{\"id\":\"p\",\"parents\":[\"q\",\"q\",\"q\"],\"effects\":{\"k\":1},\"reason\":null},"
        "{\"id\":\"q\",\"parents\":[],\"effects\":{\"k\":2},\"reason\":null}]",
    };
    for (size_t t = 0; t < sizeof(tricky)/sizeof(tricky[0]); t++)
        check_partition(tricky[t], "tricky set");
}

/* ---------------- DEFECT 3: canonical form built in a FIXED buffer ----------
 *
 * record_leaf() emitted the canon into `char buf[8192]` via fmemopen(), and
 * values_equal() emitted each side of a §5.3 comparison into `char
 * ba[4096]`. Both silently hashed/compared a PREFIX. The pinned cases are all
 * tiny, so the corpus never reached either bound and nothing failed.
 *
 * Pre-fix, with pad = 8400 'A':
 *     C leaf   45c72d357e7192a5caca7fb7ee2d1ec81fa388ff808e37a33379c12e96ea4c59
 *   = SHA-256(canon[0:8191]) exactly -- fmemopen keeps the last byte for its own
 *   NUL, so the effective buffer was 8191, not 8192, and the port never knew.
 *   C closure root d56db1363847ae6315e724df9231448119c856cae8223c551fcce506fc2f5d63
 *   reference    a25c4aace6ef1a2049f8b8219175c1ca8df4025fa4884d82693c22ab46744a88
 *                4da33bc49dc7b15324b12d40e6f3b9040ae404ed83d147669b8dd61024bb81b7
 *
 * Every expectation below is a cross-port pin: git.pp-doctor (the Python
 * reference), gitpp-js, gitpp-pl and gitpp-cs all produce the same value, so
 * these literals are not this port grading its own homework.
 */

// A one-record document whose canon carries `pad` copies of `fill` in effects.
static char *doc_with_pad(char fill, size_t pad, char last /* 0 = none */) {
    const char *head = "[{\"id\":\"big-1\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"pad\":\"";
    const char *tail = "\"},\"reason\":null}]";
    size_t need = strlen(head) + pad + 2 * strlen(tail) + 8;
    char *doc = malloc(need);
    size_t n = 0;
    for (const char *q = head; *q; q++) doc[n++] = *q;
    for (size_t i = 0; i < pad; i++) doc[n++] = fill;
    if (last) doc[n++] = last;
    for (const char *q = tail; *q; q++) doc[n++] = *q;
    doc[n] = '\0';
    return doc;
}

// A two-record document: an override and a task both set key "k", to strings
// that share their first `pad` bytes and differ only in the final character.
static char *two_key_docs(size_t pad, char win, char lose) {
    const char *fmt = "[{\"id\":\"override-1\",\"kind\":\"override\",\"parents\":[],"
                      "\"effects\":{\"k\":\"%s%c\"},\"reason\":\"set\"},"
                      "{\"id\":\"task-b\",\"kind\":\"task\",\"parents\":[],"
                      "\"effects\":{\"k\":\"%s%c\"},\"reason\":\"set\"}]";
    char *a = malloc(pad + 2), *b = malloc(pad + 2);
    memset(a, 'A', pad); a[pad] = '\0';
    memset(b, 'A', pad); b[pad] = '\0';
    char *doc = malloc(2 * pad + 512);
    sprintf(doc, fmt, a, win, b, lose);
    free(a); free(b);
    return doc;
}


/* SPEC §4 -- an incomplete closure has a NULL root.
 *
 * "If any ancestor of `at` is missing from the set, the closure is
 * incomplete and the root is `null`."
 *
 * The port used to walk the ancestor graph and SKIP any parent id that
 * was not in the record set. The missing parent was dropped silently,
 * the closure looked complete, and a root was computed over whatever
 * survived. Every other port returns null for this case; this one
 * returned a hash -- so the five ports DISAGREED and the disagreement
 * was invisible to the cross-port harness, whose accounting filed a
 * case as an "error" whenever any sibling port failed.
 *
 * The two cases below are the corpus case L2/incomplete-closure and its
 * transitive variant: a parent missing TWO HOPS up also makes the
 * closure incomplete.
 */
static void test_incomplete_closure_null_root(void) {
    section("SPEC §4 -- an incomplete closure has a NULL root");

    /* Direct: at's own parent is missing. */
    const char *inc =
        "[{\"id\":\"task-1\",\"kind\":\"task\",\"parents\":[\"missing-parent\"],\"effects\":{\"x\":1}},"
        "{\"id\":\"task-2\",\"kind\":\"task\",\"parents\":[\"task-1\"],\"effects\":{\"y\":2}}]";
    json_value_t *doc = load(inc);
    ok(doc != NULL, "the incomplete-closure document parses");
    if (doc) {
        char hex[65];
        char ids[MAX_RECORDS][256];
        memset(ids, 0, sizeof(ids));
        size_t count = 0;
        closure_root("task-2", hex, ids, &count);
        eq_str(hex, "", "a missing ancestor leaves NO root (the caller prints null)");
        ok(count == 0, "an incomplete closure contains no records in the root");
    }

    /* Transitive: the missing ancestor is TWO hops up. */
    const char *inc2 =
        "[{\"id\":\"a\",\"kind\":\"task\",\"parents\":[\"ghost\"],\"effects\":{\"x\":1}},"
        "{\"id\":\"b\",\"kind\":\"task\",\"parents\":[\"a\"],\"effects\":{\"y\":2}},"
        "{\"id\":\"c\",\"kind\":\"task\",\"parents\":[\"b\"],\"effects\":{\"z\":3}}]";
    json_value_t *doc2 = load(inc2);
    ok(doc2 != NULL, "the transitive incomplete-closure document parses");
    if (doc2) {
        char hex2[65];
        char ids2[MAX_RECORDS][256];
        memset(ids2, 0, sizeof(ids2));
        size_t count2 = 0;
        closure_root("c", hex2, ids2, &count2);
        eq_str(hex2, "", "a missing ancestor TWO HOPS UP also leaves no root");
    }

    /* The control: a COMPLETE closure still gets a real root. */
    const char *good =
        "[{\"id\":\"a\",\"kind\":\"task\",\"parents\":[],\"effects\":{\"x\":1}},"
        "{\"id\":\"b\",\"kind\":\"task\",\"parents\":[\"a\"],\"effects\":{\"y\":2}}]";
    json_value_t *doc3 = load(good);
    ok(doc3 != NULL, "the complete-closure document parses");
    if (doc3) {
        char hex3[65];
        char ids3[MAX_RECORDS][256];
        memset(ids3, 0, sizeof(ids3));
        size_t count3 = 0;
        closure_root("b", hex3, ids3, &count3);
        ok(strlen(hex3) == 64, "a COMPLETE closure still gets a 64-char root");
        ok(count3 == 2, "a complete closure contains both records");
    }
}

static void test_canon_buffer_overflow(void) {
    section("DEFECT 3 -- a canonical form larger than the emit buffer");
    char h[65];

    // 1. The canon is 8486 bytes; the old array held 8191 of them.
    char *d1 = doc_with_pad('A', 8400, 0);
    leaf_of(d1, h);
    eq_str(h, "a25c4aace6ef1a2049f8b8219175c1ca8df4025fa4884d82693c22ab46744a88",
           "an 8486-byte canonical form hashes in FULL (not its first 8191 bytes)");
    free(d1);

    // 2. The collision truncation actually caused: two records sharing their
    //    first 8191 canonical bytes are DIFFERENT records and must not alias.
    char plain[65], tail[65];
    char *d2 = doc_with_pad('A', 8400, 0);
    leaf_of(d2, plain);
    free(d2);
    char *d3 = doc_with_pad('A', 8399, 'B');   /* identical but for the last byte */
    leaf_of(d3, tail);
    free(d3);
    ok(strcmp(plain, tail) != 0,
       "records differing only AFTER the old 8192-byte boundary get different leaves");
    eq_str(tail, "54901e5eb6d86596ef5e498e4c7db0b6a3a8b68f7fa23603f8e6f1e294e1b0f5",
           "... and the second one equals the reference leaf");

    // 3. The bound must be UNBOUNDED, not merely larger. 200 KB of canon is 24x
    //    the old buffer and 24x any "just raise the constant" fix; if this one
    //    passes, no constant in this file is doing the work.
    char *d4 = doc_with_pad('Z', 200000, 0);
    leaf_of(d4, h);
    eq_str(h, "c5ee0b8ba6308affb908b6d000ffb348dae639f042eec6ba44e54f095f953a20",
           "a 200086-byte canonical form (24x the old buffer) still matches the reference");
    free(d4);

    // 4. values_equal()'s 4096 buffers, which were the worse of the two: two
    //    DIFFERENT values with a 4201-byte shared prefix compared EQUAL, so
    //    §5.3 read "no genuine disagreement" and DELETED a real conflict from
    //    the fold -- the ledger lost an entry, not just a hash.
    char *doc = two_key_docs(4200, 'X', 'Y');
    char *out = derive_of(doc);
    ok(out && strstr(out, "\"key\":\"k\"") != NULL,
       "a conflict whose values differ only after 4095 canonical bytes SURVIVES section 5.3");
    ok(out && strstr(out, "\"losers\":[\"task-b\"]") != NULL,
       "... with task-b still listed as the loser");
    if (out) free(out);
    free(doc);

    // The control: the same pair with short values. §5.3 has always kept this
    // one, so a failure above is the 4096 buffer and nothing else.
    char *ctl = two_key_docs(4, 'X', 'Y');
    char *cout = derive_of(ctl);
    ok(cout && strstr(cout, "\"key\":\"k\"") != NULL,
       "control: the same pair of short values still conflicts");
    if (cout) free(cout);
    free(ctl);
}

int main(void) {
    printf("gitpp-c regression suite\n");
    test_pinned_leaves();
    test_escapes();
    test_kind();
    test_parents_set();
    test_losers_order();
    test_orphans();
    test_canon_buffer_overflow();
    test_incomplete_closure_null_root();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
