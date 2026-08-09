#!/usr/bin/env bash
# e2e.sh — binary-level end-to-end checks against the real OTX API.
#
# The Go suite in e2e/ exercises the packages; this exercises the thing a user
# actually runs: the built binary, its exit codes, its stdout/stderr split, and
# the MCP stdio session. Those are contracts a package-level test cannot see.
#
# Network required. Run via `make e2e`, which builds first.
#
# Budget: about eight upstream requests. OTX is free and has been observed
# returning 429s and 504s under ordinary development traffic — keep it small.

set -uo pipefail

BIN="${BIN:-dist/otx-lookup}"
[ -x "$BIN" ] || { echo "FAIL: $BIN not built (run make build)"; exit 1; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

# Isolate the cache so a stale entry cannot mask a regression. The config is
# left alone: the operator's API key is what we want to exercise.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export XDG_CACHE_HOME="$WORK/cache"

pass=0; fail=0
ok()   { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
skip() { printf '  skip %s\n' "$1"; }

# check NAME EXPECTED_EXIT -- command...
check() {
  local name=$1 want=$2; shift 3
  local out; out=$("$@" 2>&1); local got=$?
  if [ "$got" = "$want" ]; then ok "$name"; else
    bad "$name (exit $got, want $want)"
    printf '       %s\n' "$(printf '%s' "$out" | head -3)"
  fi
}

# contains NAME NEEDLE -- command...
contains() {
  local name=$1 needle=$2; shift 3
  local out; out=$("$@" 2>&1)
  if printf '%s' "$out" | grep -qF -- "$needle"; then ok "$name"; else
    bad "$name (output does not contain '$needle')"
    printf '       %s\n' "$(printf '%s' "$out" | head -3)"
  fi
}

echo "==> version and help"
check "version exits 0"            0 -- "$BIN" version
check "--version exits 0"          0 -- "$BIN" --version
# A Homebrew formula's `brew test` runs --version; the two spellings must agree.
if [ "$("$BIN" version)" = "$("$BIN" --version)" ]; then
  ok "version and --version agree"
else
  bad "version and --version differ"
fi
check "help exits 0"               0 -- "$BIN" help
check "no arguments is a usage error" 2 -- "$BIN"
check "unknown command is an error"   2 -- "$BIN" nosuchcommand
contains "usage lists auth check" "auth check" -- "$BIN" help

echo "==> input validation (no network)"
check "malformed target is rejected" 2 -- "$BIN" lookup "not a target"
check "impossible section is rejected" 2 -- "$BIN" lookup 8.8.8.8 --sections whois
check "cache needs a subcommand"     2 -- "$BIN" cache
check "auth needs a subcommand"      2 -- "$BIN" auth

echo "==> live lookup"
check "reported indicator exits 0"  0 -- "$BIN" lookup paypal.com --limit 2
contains "output reports held vs shown" "pulses held" -- "$BIN" lookup paypal.com --limit 2
contains "output states provenance" "otx.alienvault.com" -- "$BIN" lookup paypal.com --limit 2
# The fallback is visible in the output, and is served from the cache above.
contains "name fallback is explained" "resolved: asked as" -- "$BIN" lookup bbc.co.uk --limit 1

echo "==> JSON output"
if "$BIN" lookup paypal.com --json --limit 1 | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  ok "lookup --json is a single JSON document"
else
  bad "lookup --json did not parse"
fi
if "$BIN" lookup --json --limit 1 paypal.com bbc.co.uk |
   python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin if l.strip()]' 2>/dev/null; then
  ok "multiple targets emit JSONL"
else
  bad "multiple targets did not emit valid JSONL"
fi

echo "==> pulse"
check "pulse detail exits 0" 0 -- "$BIN" pulse 693096c1cabeccbc6b3a5def
contains "pulse lists indicators with --indicators" "microsoft-login.com" \
  -- "$BIN" pulse 693096c1cabeccbc6b3a5def --indicators --limit 3

echo "==> cache"
contains "cache status reports the directory" "$WORK" -- "$BIN" cache status
check "cache clear exits 0" 0 -- "$BIN" cache clear
contains "cache is empty after clear" "entries: 0" -- "$BIN" cache status

echo "==> auth"
if "$BIN" auth check --json | python3 -c '
import json,sys
st = json.load(sys.stdin)
assert st["status"] in ("valid","rejected","unreachable","absent"), st["status"]
' 2>/dev/null; then
  ok "auth check reports one of the four states"
else
  bad "auth check did not report a valid state"
fi
check "a rejected key does not exit 0" 2 -- env OTX_LOOKUP_API_KEY=0000000000000000000000000000000000000000000000000000000000000000 "$BIN" auth check
contains "a rejected key says so" "REJECTED" \
  -- env OTX_LOOKUP_API_KEY=0000000000000000000000000000000000000000000000000000000000000000 "$BIN" auth check
# The one thing a key-handling command must never do.
if env OTX_LOOKUP_API_KEY=sentinel-key-value "$BIN" auth check 2>&1 | grep -q "sentinel-key-value"; then
  bad "auth check printed the API key"
else
  ok "auth check never prints the key"
fi

echo "==> MCP stdio session"
MCP_OUT="$WORK/mcp.jsonl"
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_usage","arguments":{}}}'
  echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cache_status","arguments":{}}}'
} | "$BIN" mcp > "$MCP_OUT" 2>/dev/null
if python3 - "$MCP_OUT" <<'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
ids = [m.get("id") for m in lines]
assert ids == [1, 2, 3, 4], f"ids {ids}: a notification was answered, or a reply is missing"
assert lines[0]["result"]["serverInfo"]["name"] == "otx-lookup"
names = {t["name"] for t in lines[1]["result"]["tools"]}
assert names == {"lookup_indicator", "get_pulse", "search_pulses", "cache_status", "get_usage"}, names
assert "otx-lookup MCP server" in lines[2]["result"]["content"][0]["text"]
json.loads(lines[3]["result"]["content"][0]["text"])
PY
then
  ok "MCP session: initialize, tools/list, get_usage, cache_status"
else
  bad "MCP session did not behave as expected"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
