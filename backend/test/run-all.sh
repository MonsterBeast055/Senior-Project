#!/usr/bin/env bash
#
# run-all.sh - Every contract suite, each against its own fresh run.
#
# The per-suite fresh upload is not tidiness. The suites mutate state: the
# versioning one posts a manual lift, which makes the findings suite's rows stale
# and changes what it sees. Sharing a run between them produces a failure that
# looks like a product bug and is not one - which cost real time to chase down
# once already.
#
#   ./test/run-all.sh                    # uses the fake engine
#   SP_BINARY=/path/to/sp ./test/run-all.sh
#
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PORT="${PORT:-3399}"
BASE="http://localhost:${PORT}/api"
DATA="$(mktemp -d)"
ENGINE="${SP_BINARY:-$HERE/fake-engine.sh}"

SAMPLE="$(mktemp)"
head -c 4096 /bin/ls > "$SAMPLE" 2>/dev/null || head -c 4096 /bin/sh > "$SAMPLE"

SP_BINARY="$ENGINE" DATA_DIR="$DATA" PORT="$PORT" node "$ROOT/server.js" > "$DATA/server.log" 2>&1 &
SERVER=$!
cleanup() { kill "$SERVER" 2>/dev/null; rm -rf "$DATA" "$SAMPLE"; }
trap cleanup EXIT

for _ in $(seq 1 40); do
    curl -sf "$BASE/health" > /dev/null 2>&1 && break
    sleep 0.5
done

# One fresh run per suite.
new_run() {
    local id
    id=$(curl -sS -F "binary=@${SAMPLE};filename=sample.exe" "$BASE/runs" \
         | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).run_id))")
    for _ in $(seq 1 40); do
        local stage
        stage=$(curl -sS "$BASE/runs/$id/status" \
                | node -e "let d='';process.stdin.on('data',c=>c&&(d+=c)).on('end',()=>console.log(JSON.parse(d).stage))")
        [ "$stage" = "done" ] && break
        [ "$stage" = "failed" ] && { echo "analysis failed for $id" >&2; return 1; }
        sleep 0.4
    done
    echo "$id"
}

FAILED=0
for suite in contract ai-contract findings-box-contract versioning-contract; do
    [ -f "$HERE/$suite.mjs" ] || continue
    RUN=$(new_run) || { FAILED=$((FAILED + 1)); continue; }
    printf '%-26s ' "$suite"
    if node "$HERE/$suite.mjs" "$BASE" "$RUN" > "$DATA/$suite.out" 2>&1; then
        tail -1 "$DATA/$suite.out"
    else
        FAILED=$((FAILED + 1))
        echo "FAILED"
        grep -E '^FAIL' "$DATA/$suite.out" | sed 's/^/    /'
    fi
done

echo
if grep -qiE 'unhandled|uncaught|TypeError' "$DATA/server.log"; then
    echo "server logged an error:"
    grep -iE 'unhandled|uncaught|TypeError' "$DATA/server.log" | head -5
    FAILED=$((FAILED + 1))
else
    echo "server log clean"
fi

[ "$FAILED" -eq 0 ] && echo "all suites passed" || echo "$FAILED suite(s) failed"
exit "$FAILED"
