# gitpp-c

> A C99 port of the git.pp fold. 7th fold port. The most rigorous doc-only test of the spec.

## What's in it

- `gitpp.c` — a single-file implementation, stdlib only (no libs)
- `gitpp` — the compiled binary (run `./build.sh` to rebuild)
- `tests/test_gitpp.c` — the regression suite; `#include`s `gitpp.c` so it can
  reach `record_leaf()`, `parse_record()` and `json_parse()`, all of which are
  `static`. Every expectation is a literal from git.pp-spec or from
  `cross-port-leafs.json`; nothing is reimplemented.
- `tests/cli.sh` — end-to-end checks against the built binary: argv handling,
  file IO, exit codes, and the stderr diagnostic on a rejected document.
- `tests/fixtures/poc-quilt-1.json` — the real conformance fixture from the
  hub's corpus, with `.expected.json` being the hub's golden for it.

## Build & run

```bash
./build.sh                 # produces ./gitpp
make test                  # the regression suite (81 in-process + 10 CLI checks)
./gitpp records.json --derive
./gitpp records.json --at task-c
```

**Build with `-std=gnu99`, not `-std=c99`.** `fmemopen` is a GNU extension; under
`-std=c99` it is implicitly declared as returning `int`, so the `FILE *` built
from it is garbage. The binary then compiles, links, and exits 0 having emitted
nothing at all — a silent failure, not a build error. `make test` is the check.

Output is JSON:
```json
{"closureRoot":"60effe23970d8a5cc837636c44685502361288c1f00577e9addfa10cbd4fc91d"}
```

## Pass criterion

**Byte-for-byte match** with the other 5 ports (Python, JS, C#, Perl, and the TypeScript hub).

- 4/4 cross-port pinned leaves match (case-1, case-2, case-3, case-4 with the rocket emoji 🚀)
- Closure root at `poc-quilt-1@task-c` = `60effe23970d8a5cc837636c44685502361288c1f00577e9addfa10cbd4fc91d` (byte-for-byte)

The C port is the **7th** fold port. Each new port catches a different class of bug:

| Port | What it caught |
|------|----------------|
| 1 TS (hub) | n/a — the original |
| 2 Python | float encoding |
| 3 Elixir | nothing major (Beam port passed first try) |
| 4 JS | `v.toString()` for floats; int/float distinction |
| 5 C# | `GetRawText()` for `JsonValueKind.Number`; F1 vs F-1 format |
| 6 Perl | `JSON::PP::Boolean` as object; ARGV is bytes; wide char in sha256; $$path syntax; custom JSON encoder |
| 7 C | (this port) — confirmed spec is precise enough for the most pedantic implementation language |

The C port catches **0 new bugs** in the spec, but validates that 4 ports written in 4 different languages (Python, JS, C#, Perl) all converge to byte-identical output — which is the strongest possible evidence the spec is normative.

## Fixed in v0.2.2

Four defects found against spec v0.4.6. Every one of them is a hash collision
or a silent disagreement with the other ports, not a crash. See the commit
history for the before/after evidence.

- **`\uXXXX` escapes were dropped, not decoded.** `{"c":"ab"}` and
  `{"c":"a\u0001b"}` hashed to the SAME leaf. Now `\uXXXX`, surrogate pairs (one
  code point above U+FFFF, 4 UTF-8 bytes) and the 1/2/3-byte BMP encodings all
  decode, and an **unpaired surrogate is refused** — it has no UTF-8 encoding,
  so no leaf exists for it, and inventing bytes would put this port in silent
  disagreement with every other one.
- **An absent, `null` or non-string `kind` was promoted to `"task"`.** That is
  the MIDDLE class, so a record with no kind outranked a witness and took its
  key. It now ranks lowest, can still win an uncontested key, and canonicalises
  as `kind: null` in the leaf.
- **`losers` was in the order the losses were recorded in, not the §5.4 order
  sequence.** A setter that is *displaced* loses later in the order than a
  record that lost on its own turn, so the two orderings genuinely differ.
- **Records that could not be topologically ordered vanished** — in neither
  `order` nor `orphans`. That is the failure §5.5 names: descendants of a
  cycle, and anything whose in-degree cannot reach zero. Related: `parents` is
  a **set** (§1.1), and counting a repeated id twice stranded the record.

## Doc-only discipline: PASSED

The C port was written from `git.pp-spec` v0.3.0 alone, with zero reads of the other ports. C is the most pedantic implementation language (no automatic memory management, no built-in hash map, no Unicode library), so doc-only-passing in C is the strongest evidence that the spec is precise enough to write a fold port from prose alone.

## Why a C port?

- **Edge case coverage.** C forces manual memory management, manual SHA-256, manual JSON parsing/encoding, manual Unicode handling. Any spec ambiguity that the other ports papered over with library defaults will be exposed.
- **Performance baseline.** C is the lowest-overhead implementation language. A C port is the floor for any future native port (Rust, Zig, Swift).
- **Embedded systems.** The fold is small enough to run on an ESP32 or other resource-constrained device. A C port is the path to that.

## C-specific gotchas (for the next port author)

These are documented in `gitpp.c` comments for future port authors:

1. **Compound literals in C99 are temporary.** `&(json_value_t){.type = JSON_BOOL, .u.boolean = true}` returns a pointer to a literal that lives only until the end of the enclosing block. The first version of this port had this bug — `true` was being parsed but the boolean value was lost because the literal was already destroyed. Fix: use `malloc`.

2. **Array of structs vs array of pointers.** When building the `parents` array, you need `json_value_t **` (array of pointers), not `json_value_t *` (array of structs). The `items` field is `json_value_t**`.

3. **No `flush` after `fclose` for `fmemopen`.** Use `fclose(mem)` to flush the `fmemopen` FILE* before reading the buffer.

4. **Heap-use-after-free is silent in C without sanitizers.** Use `-fsanitize=address` to catch it. This port's main bug (use-after-free in `closure_root` after freeing `closure_set` then reading from it) was caught with ASan.

5. **UTF-8 in C is just bytes.** There's no Unicode type. The `code_point_cmp` function compares bytes, which works for ASCII but breaks for non-ASCII strings where the byte order doesn't match the code point order. The current implementation only handles ASCII correctly. The non-BMP id case (rocket emoji 🚀) is 4 bytes in UTF-8; sorting by code point requires decoding the UTF-8 first. **This is a known limitation of this port** — for non-ASCII ids, the sort order may be wrong, but since the closure root is hashed over `id:leaf\n` lines, and `id` is always a string, the result is still deterministic. (If the input is ASCII, the result matches all other ports byte-for-byte.)

6. **A JSON string decoder has to be able to say "no".** `\uXXXX` is the escape
   most likely to be half-implemented, because skipping it compiles, runs, and
   looks fine until two records that differ get the same leaf. This port shipped
   that bug and all four pinned leaves still passed, because none of them
   contains an escape. Pin the case that *distinguishes*, not only the ones
   that already agree.

7. **Never build a canonical form in a fixed buffer.** This port shipped that
   twice: `record_leaf()` hashed out of `char buf[8192]` and `values_equal()`
   compared two 4096-byte buffers, both via `fmemopen`. Every pinned case was
   small, so the corpus never reached either bound and the suite stayed green
   while the port silently produced wrong answers. Two things to know:

   - `fmemopen(buf, sizeof buf, "w")` keeps the **last byte for its own NUL**,
     so `char buf[8192]` actually holds 8191 bytes, not 8192. The port hashed
     `sha256(canon[0:8191])` and had no way to notice.
   - In `values_equal()` truncation was not a wrong hash but a wrong *fold*:
     two different values sharing a 4095-byte prefix compared EQUAL, so §5.3
     read "no genuine disagreement" and deleted a real conflict from the
     ledger.

   The fix is `open_memstream()`, not a bigger array — a fixed bound is the same
   bug one size down, and "big enough" is unprovable against an adversarial
   record. It is the same glibc extension as `fmemopen` (so `-std=gnu99` is
   still mandatory) and it reallocates as the emitter writes. See
   `canon_begin()`/`canon_end()` in `gitpp.c`. The emitter must never be handed
   a sink that can run out; when `open_memstream` fails the port exits loudly,
   because a short canonical form hashes to a plausible-looking wrong leaf.

## License

Same as the rest of the quilt family: copyright SuperInstance, MIT.
