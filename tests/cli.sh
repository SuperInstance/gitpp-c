#!/usr/bin/env bash
# cli.sh -- end-to-end checks against the BUILT binary.
#
# tests/test_gitpp.c covers leaves and fold semantics in-process (it has to
# #include gitpp.c, because record_leaf() and parse_record() are static). This
# covers what only the binary can: argv handling, file IO, exit codes and the
# stderr diagnostic on a rejected document.
#
# The poc-quilt-1 receipt is the real conformance fixture from the hub's
# conformance corpus (patchwork-quilt/git.pp-ng conformance/live-records.json
# and live-golden.json), which is where this port's documented pass criterion
# comes from: closure root at poc-quilt-1@task-c =
# 60effe23970d8a5cc837636c44685502361288c1f00577e9addfa10cbd4fc91d
set -u
GITPP="${1:-./gitpp}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0

check() { # <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    echo "  ok   $1"; pass=$((pass + 1))
  else
    echo "  FAIL $1"; echo "         got      $3"; echo "         expected $2"; fail=$((fail + 1))
  fi
}

echo "== cli.sh -- the built binary =="

# --- the port's documented pass criterion -------------------------------
out=$("$GITPP" "$DIR/fixtures/poc-quilt-1.json" --at task-c)
check "closure root at poc-quilt-1@task-c (the documented pass criterion)" \
      '{"closureRoot":"60effe23970d8a5cc837636c44685502361288c1f00577e9addfa10cbd4fc91d"}' "$out"

# --- derive() against the hub's golden ---------------------------------
"$GITPP" "$DIR/fixtures/poc-quilt-1.json" --derive > "$TMP/derived.json"
for member in state order orphans; do
  got=$(python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))['$member'],sort_keys=True))" \
        "$TMP/derived.json")
  want=$(python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))['$member'],sort_keys=True))" \
        "$DIR/fixtures/poc-quilt-1.expected.json")
  check "poc-quilt-1 $member matches the hub's golden" "$want" "$got"
done
got=$(python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))['conflicts'],sort_keys=True))" \
      "$TMP/derived.json")
want=$(python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))['conflicts'],sort_keys=True))" \
       "$DIR/fixtures/poc-quilt-1.expected.json")
check "poc-quilt-1 conflicts match the hub's golden, losers order included" "$want" "$got"

# --- DEFECT 1: the collision, end to end --------------------------------
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"ab"},"reason":null}]' > "$TMP/plain.json"
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"a\\u0001b"},"reason":null}]' > "$TMP/esc.json"
a=$("$GITPP" "$TMP/plain.json" --at r)
b=$("$GITPP" "$TMP/esc.json"  --at r)
if [ "$a" != "$b" ]; then
  echo "  ok   {\"c\":\"ab\"} and {\"c\":\"a\\u0001b\"} get different closure roots"; pass=$((pass + 1))
  echo "         $a  ab"
  echo "         $b  a\\u0001b"
else
  echo "  FAIL the \\uXXXX collision persists: both are $a"; fail=$((fail + 1))
fi

# a surrogate PAIR must decode, not be rejected
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"\\ud83d\\ude80"},"reason":null}]' > "$TMP/rocket.json"
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"\\ud83d\\ude80"},"reason":null}]' > "$TMP/rocket.json"
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"\xf0\x9f\x9a\x80"},"reason":null}]' > "$TMP/rocketlit.json"
c=$("$GITPP" "$TMP/rocket.json" --at r)
d=$("$GITPP" "$TMP/rocketlit.json" --at r)
check "a \\uD83D\\uDE80 pair equals the literal 4-byte emoji" "$d" "$c"

# --- an unpaired surrogate must be REFUSED, not mangled -----------------
printf '[{"id":"r","kind":"task","parents":[],"effects":{"c":"\\ud800"},"reason":null}]' > "$TMP/lone.json"
err=$("$GITPP" "$TMP/lone.json" --derive 2>&1 >/dev/null); rc=$?
if [ "$rc" -ne 0 ] && [ -n "$err" ]; then
  echo "  ok   a lone high surrogate is refused (exit $rc): $err"; pass=$((pass + 1))
else
  echo "  FAIL a lone high surrogate was accepted (exit $rc, stderr '$err')"; fail=$((fail + 1))
fi

# --- DEFECT 2: a kindless record must not outrank a witness -------------
printf '[{"id":"a","kind":"witness","parents":[],"effects":{"x":"W"},"reason":null},{"id":"b","parents":["a"],"effects":{"x":"OMITTED"},"reason":null}]' > "$TMP/omit.json"
got=$("$GITPP" "$TMP/omit.json" --derive | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['state']))")
check "a record with no kind loses to a witness" '{"x": "W"}' "$got"

# --- DEFECT 3: a canonical form LARGER than the old 8192-byte emit buffer --
# The harness covers the leaf; this covers the number that actually ships, the
# closure root, end to end through argv, file IO and the hashing in main().
# pad is 8400 bytes, so the canon is 8486 -- 295 bytes past what buf[8192] held.
python3 -c "import json,sys; json.dump([{'id':'big-1','parents':[],'kind':'task','effects':{'pad':'A'*8400},'reason':None}], open(sys.argv[1],'w'))" "$TMP/big.json"
got=$("$GITPP" "$TMP/big.json" --at big-1)
check "closure root of an 8486-byte canonical form (past the old 8 KiB buffer)" \
      '{"closureRoot":"4da33bc49dc7b15324b12d40e6f3b9040ae404ed83d147669b8dd61024bb81b7"}' "$got"

# Provenance: the pre-fix port returned
#   d56db1363847ae6315e724df9231448119c856cae8223c551fcce506fc2f5d63
# for this input, which is sha256("big-1:" + sha256(canon[0:8191])) -- the root
# of the record's first 8191 canonical bytes and not the record.

# ... and it must not be a "bigger buffer": 200 KB of canon is 24x the old array
# and 24x any "just raise the constant" fix, so this cannot pass by luck.
# Closure root pinned from git.pp-doctor, the Python reference port; the same
# value is reproduced by gitpp-js, gitpp-pl and gitpp-cs.
python3 -c "import json,sys; json.dump([{'id':'big-1','parents':[],'kind':'task','effects':{'pad':'Z'*200000},'reason':None}], open(sys.argv[1],'w'))" "$TMP/huge.json"
check "closure root of a 200086-byte canonical form (no fixed bound at all)" \
      '{"closureRoot":"adbe102e0740b45f6aa9c59e8a5301b82a0675d5d813cdd5ad1e140a1fb28eb1"}' \
      "$("$GITPP" "$TMP/huge.json" --at big-1)"

# 4 MiB of canon. Nothing in a source file can be "big enough" against this,
# so it is the check that makes the bound a claim rather than a constant.
python3 -c "import json,sys; json.dump([{'id':'big-1','parents':[],'kind':'task','effects':{'pad':'A'*(4*1024*1024)},'reason':None}], open(sys.argv[1],'w'))" "$TMP/vast.json"
check "closure root of a 4 MiB canonical form (adversarial)" \
      '{"closureRoot":"24a5dd5b5f82bea16f92da849652369685dad23f6771196ab8fc148aad3a10d7"}' \
      "$("$GITPP" "$TMP/vast.json" --at big-1)"

# --- a well-formed document still works ---------------------------------
check "no --at and no --derive is still an error" '{"error":"no --at"}' \
      "$("$GITPP" "$TMP/omit.json")"

echo ""
echo "cli.sh: $((pass + fail)) checks, $fail failures"
[ "$fail" -eq 0 ]
