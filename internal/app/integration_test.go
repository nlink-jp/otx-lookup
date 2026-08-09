package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate points config and cache at a temp dir, clears the tool's environment
// so a developer's real key is never used, and routes the client at a stub
// server. Every integration test runs the whole flags → config → engine → otx
// → output path against it.
func isolate(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{
		"OTX_LOOKUP_API_KEY", "OTX_API_KEY", "OTX_LOOKUP_DEFAULT_LIMIT",
		"OTX_LOOKUP_CACHE_DIR", "OTX_LOOKUP_CACHE_TTL_HOURS",
		"OTX_LOOKUP_TIMEOUT_SECONDS", "OTX_LOOKUP_MAX_PER_HOUR",
		"OTX_LOOKUP_MCP_INLINE_MAX", "OTX_LOOKUP_WORKSPACE",
	} {
		t.Setenv(k, "")
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	t.Setenv("OTX_LOOKUP_BASE_URL", srv.URL)
	return srv
}

// routes serves canned bodies by request path; anything unrouted is a 404, the
// same as upstream.
func routes(m map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := m[r.URL.EscapedPath()]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"not found"}`))
			return
		}
		w.Write([]byte(body))
	}
}

const richBody = `{
  "indicator": "evil.test", "type": "domain",
  "validation": [], "false_positive": [],
  "pulse_info": {"count": 3, "references": ["https://example.test/r"], "pulses": [
    {"id":"p1","name":"Qakbot infrastructure","modified":"2026-08-01T00:00:00.000000",
     "created":"2026-01-01T00:00:00.000000","author":{"username":"analyst"},"TLP":"green",
     "adversary":"APT-X","malware_families":[{"id":"Qakbot","display_name":"Qakbot"}],
     "attack_ids":[{"id":"T1041","name":"Exfil","display_name":"T1041 - Exfil"}],
     "industries":["Finance"],"targeted_countries":["Japan"],"tags":["c2"],"indicator_count":12},
    {"id":"p2","name":"Older report","modified":"2026-02-01T00:00:00.000000",
     "created":"2026-02-01T00:00:00.000000","author":{"username":"other"},"tags":["phishing"]},
    {"id":"p3","name":"Oldest report","modified":"2026-01-15T00:00:00.000000",
     "created":"2026-01-15T00:00:00.000000","author":{"username":"third"}}
  ]}}`

const emptyBody = `{"indicator":"quiet.test","type":"domain","pulse_info":{"count":0,"pulses":[]}}`

func lookup(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	// A nil reader stands for "no pipe attached", so a test that passes no
	// stdin never blocks waiting on one.
	var in io.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	code := run(append([]string{"lookup"}, args...), "test", in, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestLookupTextOutput(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	code, out, errOut := lookup(t, "", "evil.test")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, errOut)
	}
	for _, want := range []string{
		"evil.test", "[domain]", "3 pulses",
		"adversary:", "APT-X (1)",
		"malware:", "Qakbot (1)",
		"ATT&CK:", "T1041 - Exfil (1)",
		"industries:", "Finance (1)",
		"targeting:", "Japan (1)",
		"reported: 2026-01-01 .. 2026-08-01",
		"Qakbot infrastructure", "analyst", "p1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	// Newest first.
	if strings.Index(out, "Qakbot infrastructure") > strings.Index(out, "Oldest report") {
		t.Errorf("pulses are not newest-first:\n%s", out)
	}
}

// Zero pulses is a successful answer, and the output has to say so plainly
// rather than looking like a failure.
func TestLookupNoPulsesSucceeds(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/indicators/domain/quiet.test/general":   emptyBody,
		"/indicators/hostname/quiet.test/general": emptyBody,
	}))

	code, out, errOut := lookup(t, "", "quiet.test")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, errOut)
	}
	if !strings.Contains(out, "no community report names this indicator") {
		t.Errorf("output does not state the empty result plainly:\n%s", out)
	}
}

// The domain/hostname fallback must be visible: which type answered is part of
// the answer, not an implementation detail.
func TestLookupReportsWhichTypeAnswered(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/indicators/hostname/bbc.co.uk/general": `{"indicator":"bbc.co.uk","pulse_info":{"count":0,"pulses":[]}}`,
		"/indicators/domain/bbc.co.uk/general": `{"indicator":"bbc.co.uk","pulse_info":{"count":1,"pulses":[
		  {"id":"px","name":"Report","modified":"2026-08-01T00:00:00.000000","author":{"username":"a"}}]}}`,
	}))

	code, out, errOut := lookup(t, "", "bbc.co.uk")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "resolved: asked as hostname, then domain; domain answered") {
		t.Errorf("output does not explain the fallback:\n%s", out)
	}
}

func TestLookupJSONOutput(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	code, out, errOut := lookup(t, "", "--json", "evil.test")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	var res struct {
		Query       string `json:"query"`
		Type        string `json:"type"`
		PulsesHeld  int    `json:"pulses_held"`
		PulsesShown int    `json:"pulses_shown"`
		Context     struct {
			Adversaries []struct {
				Value  string `json:"value"`
				Pulses int    `json:"pulses"`
			} `json:"adversaries"`
		} `json:"context"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if res.Query != "evil.test" || res.Type != "domain" {
		t.Errorf("query/type = %q/%q", res.Query, res.Type)
	}
	if res.PulsesHeld != 3 || res.PulsesShown != 3 {
		t.Errorf("held/shown = %d/%d, want 3/3", res.PulsesHeld, res.PulsesShown)
	}
	if len(res.Context.Adversaries) != 1 || res.Context.Adversaries[0].Value != "APT-X" {
		t.Errorf("context.adversaries = %+v", res.Context.Adversaries)
	}
}

// Multiple targets emit JSONL — one object per line, so the output streams into
// jq or a log pipeline.
func TestLookupJSONLForMultipleTargets(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/indicators/domain/evil.test/general":    richBody,
		"/indicators/domain/quiet.test/general":   emptyBody,
		"/indicators/hostname/quiet.test/general": emptyBody,
	}))

	code, out, errOut := lookup(t, "", "--json", "evil.test", "quiet.test")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 (JSONL):\n%s", len(lines), out)
	}
	for i, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("line %d is not a complete JSON object: %s", i, l)
		}
	}
}

func TestLookupBulkFromFileAndStdin(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/indicators/domain/evil.test/general":    richBody,
		"/indicators/domain/quiet.test/general":   emptyBody,
		"/indicators/hostname/quiet.test/general": emptyBody,
	}))

	// Comments and blank lines are skipped, so a hand-annotated target list works.
	file := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(file, []byte("# from the alert\nevil.test\n\nquiet.test\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, out, errOut := lookup(t, "", "--json", "--input", file)
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 2 {
		t.Errorf("file input produced %d results, want 2:\n%s", n, out)
	}

	code, out, errOut = lookup(t, "evil.test\nquiet.test\n", "--json", "--input", "-")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 2 {
		t.Errorf("stdin input produced %d results, want 2:\n%s", n, out)
	}
}

// A malformed target is the operator's own mistake: exit 2, and no request.
func TestInvalidTargetExitsTwoWithoutRequesting(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(emptyBody))
	})

	code, _, errOut := lookup(t, "", "not a target")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if requests != 0 {
		t.Errorf("%d request(s) sent for an invalid target", requests)
	}
	if !strings.Contains(errOut, "not a target") {
		t.Errorf("stderr does not name the rejected target: %s", errOut)
	}
}

// An upstream outage is exit 1, distinct from the operator's own mistake.
func TestUpstreamFailureExitsOne(t *testing.T) {
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"detail":"boom"}`))
	})

	code, _, errOut := lookup(t, "", "evil.test")
	if code != exitPartial {
		t.Errorf("exit = %d, want %d", code, exitPartial)
	}
	if !strings.Contains(errOut, "evil.test") {
		t.Errorf("stderr does not name the failed target: %s", errOut)
	}
}

// What succeeded is still printed when something else failed.
func TestPartialRunPrintsWhatSucceeded(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	// broken.test is routed nowhere, so it 404s.
	code, out, _ := lookup(t, "", "--json", "evil.test", "broken.test")
	if code != exitPartial {
		t.Errorf("exit = %d, want %d", code, exitPartial)
	}
	if !strings.Contains(out, "evil.test") {
		t.Errorf("the successful target was not printed:\n%s", out)
	}
}

// The default set must never fetch a section a sibling tool owns.
func TestDefaultFetchesOnlyGeneral(t *testing.T) {
	var paths []string
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		w.Write([]byte(richBody))
	})

	if code, _, errOut := lookup(t, "", "evil.test"); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	for _, p := range paths {
		if !strings.HasSuffix(p, "/general") {
			t.Errorf("fetched %q by default; only general should be", p)
		}
	}
}

func TestSectionsFlagFetchesTheExtraSection(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/indicators/IPv4/8.8.8.8/general":    `{"indicator":"8.8.8.8","pulse_info":{"count":0,"pulses":[]}}`,
		"/indicators/IPv4/8.8.8.8/reputation": `{"reputation":0}`,
	}))

	code, out, errOut := lookup(t, "", "--json", "--sections", "reputation", "8.8.8.8")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	var res struct {
		Sections map[string]json.RawMessage `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if _, ok := res.Sections["reputation"]; !ok {
		t.Errorf("reputation section missing from the result: %v", res.Sections)
	}
}

// Asking for a section the type does not have is a usage error, caught before
// any request.
func TestUnknownSectionIsAUsageError(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(emptyBody))
	})

	code, _, errOut := lookup(t, "", "--sections", "whois", "8.8.8.8")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if requests != 0 {
		t.Errorf("%d request(s) spent on an impossible section", requests)
	}
	if !strings.Contains(errOut, "whois") {
		t.Errorf("stderr does not name the section: %s", errOut)
	}
}

func TestLimitCapsAndMarksTheResult(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	code, out, errOut := lookup(t, "", "--limit", "1", "evil.test")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "CAPPED") {
		t.Errorf("a truncated list was not marked:\n%s", out)
	}
	if !strings.Contains(out, "3 pulses held, 1 shown") {
		t.Errorf("held-vs-shown was not reported:\n%s", out)
	}
}

// --anonymous must drop a configured key. A keyed query is recorded against the
// operator's OTX account, so this is an OpSec control, not a convenience.
func TestAnonymousDropsTheConfiguredKey(t *testing.T) {
	var sawKey string
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("X-OTX-API-KEY")
		w.Write([]byte(richBody))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "secret-key")

	if code, _, errOut := lookup(t, "", "evil.test"); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if sawKey != "secret-key" {
		t.Fatalf("the configured key was not sent: %q", sawKey)
	}

	sawKey = ""
	if code, _, errOut := lookup(t, "", "--anonymous", "evil.test"); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if sawKey != "" {
		t.Errorf("--anonymous still sent a key: %q", sawKey)
	}
}

// The output must never print the key, whatever else it reports.
func TestOutputNeverPrintsTheKey(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))
	t.Setenv("OTX_LOOKUP_API_KEY", "super-secret-key")

	for _, args := range [][]string{{"evil.test"}, {"--json", "evil.test"}} {
		_, out, errOut := lookup(t, "", args...)
		if strings.Contains(out, "super-secret-key") || strings.Contains(errOut, "super-secret-key") {
			t.Errorf("the API key was printed for %v", args)
		}
	}
	// It should still say whether it was authenticated — that is provenance,
	// not the secret.
	_, out, _ := lookup(t, "", "--refresh", "evil.test")
	if !strings.Contains(out, "authenticated") {
		t.Errorf("output does not report the auth state:\n%s", out)
	}
}

// The cache saves the second request, and --refresh goes back upstream.
func TestCacheAndRefresh(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(richBody))
	})

	if code, _, _ := lookup(t, "", "evil.test"); code != exitOK {
		t.Fatal("first lookup failed")
	}
	if code, out, _ := lookup(t, "", "evil.test"); code != exitOK {
		t.Fatal("second lookup failed")
	} else if !strings.Contains(out, "cached") {
		t.Errorf("the second lookup did not report a cache hit:\n%s", out)
	}
	if requests != 1 {
		t.Errorf("%d upstream requests, want 1", requests)
	}

	if code, _, _ := lookup(t, "", "--refresh", "evil.test"); code != exitOK {
		t.Fatal("refresh lookup failed")
	}
	if requests != 2 {
		t.Errorf("--refresh made %d total requests, want 2", requests)
	}
}

// End to end, the defect that a live run exposed: one indicator type 429s, the
// other answers with no pulses, and without this the CLI printed "no community
// report names this indicator" and exited 0 — a clean bill of health invented
// out of a transient error.
func TestInconclusiveEmptyResultIsLoudAndExitsNonZero(t *testing.T) {
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.EscapedPath(), "/domain/") {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"detail":"rate limited"}`))
			return
		}
		w.Write([]byte(`{"indicator":"paypal.com","pulse_info":{"count":0,"pulses":[]}}`))
	})

	code, out, _ := lookup(t, "", "paypal.com")
	if code == exitOK {
		t.Error("exited 0 on an unverified empty result; a script would read that as clean")
	}
	if !strings.Contains(out, "INCONCLUSIVE") {
		t.Errorf("output does not flag the result as inconclusive:\n%s", out)
	}
	if strings.Contains(out, "no community report names this indicator") {
		t.Errorf("an unverified result claimed a clean answer:\n%s", out)
	}
	if !strings.Contains(out, "unavailable: type domain") {
		t.Errorf("output does not name the failed type:\n%s", out)
	}
}

// Flags must work after the target as well as before it. Go's flag package
// stops at the first positional, so without explicit handling `lookup evil.test
// --limit 1` would read the flag as two more targets and silently ignore it.
func TestFlagsWorkAfterTheTarget(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	code, out, errOut := lookup(t, "", "evil.test", "--limit", "1")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, errOut)
	}
	if !strings.Contains(out, "3 pulses held, 1 shown") {
		t.Errorf("a trailing --limit was ignored:\n%s", out)
	}
	if strings.Contains(errOut, "not a lookup target") {
		t.Errorf("a trailing flag was read as a target: %s", errOut)
	}

	// And interleaved with several targets.
	code, out, errOut = lookup(t, "", "--json", "evil.test", "--limit", "1", "evil.test")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 2 {
		t.Errorf("interleaved parse produced %d results, want 2:\n%s", n, out)
	}
}

func TestNoTargetsIsAUsageError(t *testing.T) {
	isolate(t, routes(nil))
	code, _, errOut := lookup(t, "")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut, "no targets") {
		t.Errorf("stderr does not explain the problem: %s", errOut)
	}
}
