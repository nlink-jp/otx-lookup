package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A pulse detail as the live API returns it: the indicators are embedded, the
// id is a number, is_active is 0/1, expiration may be null, and there is no
// total anywhere in the response.
const pulseDetailBody = `{
  "id": "693096c1cabeccbc6b3a5def",
  "name": "Phishing Domain Patterns",
  "description": "Brand impersonation domains.",
  "author": {"username": "reporter", "id": "42"},
  "author_name": "reporter",
  "created": "2025-12-03T20:00:01.385000",
  "modified": "2026-08-01T10:00:00.000000",
  "TLP": "white", "public": 1, "revision": 3,
  "adversary": "APT-X",
  "malware_families": [{"id":"Qakbot","display_name":"Qakbot"}],
  "attack_ids": [{"id":"T1041","name":"Exfil","display_name":"T1041 - Exfil"}],
  "industries": ["Finance"], "targeted_countries": ["Japan"],
  "tags": ["phishing","brand"],
  "references": ["https://example.test/report"],
  "indicators": [
    {"id":4157203540,"indicator":"microsoft-login.com","type":"domain",
     "created":"2025-12-03T20:00:02","content":"","title":"",
     "description":"Microsoft phishing pattern","expiration":null,"is_active":1},
    {"id":4157203541,"indicator":"retired.example","type":"domain",
     "created":"2025-11-01T10:00:00","content":"","title":"",
     "description":"","expiration":null,"is_active":0}
  ]}`

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, "test", nil, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestPulseDetailRendersAnonymously(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/pulses/693096c1cabeccbc6b3a5def": pulseDetailBody,
	}))

	code, out, errOut := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	for _, want := range []string{
		"Phishing Domain Patterns", "693096c1cabeccbc6b3a5def",
		"author reporter", "TLP:white", "revision 3",
		"adversary:", "APT-X", "malware:", "Qakbot", "T1041 - Exfil",
		"https://example.test/report",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	// Without --indicators the list is not printed, but the way to get it is.
	if strings.Contains(out, "microsoft-login.com") {
		t.Errorf("indicators were listed without --indicators:\n%s", out)
	}
	if !strings.Contains(out, "--indicators") {
		t.Errorf("output does not mention how to list indicators:\n%s", out)
	}
}

// The pivot works without a key, because the detail embeds the indicators.
func TestPulseIndicatorsWorkWithoutAKey(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/pulses/693096c1cabeccbc6b3a5def": pulseDetailBody,
	}))

	code, out, errOut := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def", "--indicators")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "microsoft-login.com") {
		t.Errorf("the embedded indicators were not listed:\n%s", out)
	}
	if !strings.Contains(out, "inactive") {
		t.Errorf("is_active=0 was not surfaced:\n%s", out)
	}
	// And the count must say where it came from: the detail states no total,
	// so presenting one as upstream's would be an invention.
	if !strings.Contains(out, "upstream states no total here") {
		t.Errorf("the unconfirmed count was not qualified:\n%s", out)
	}
	if !strings.Contains(out, "an API key confirms it") {
		t.Errorf("output does not say what would confirm the count:\n%s", out)
	}
}

// With a key the paginated endpoint answers, and only then is the count exact.
func TestPulseIndicatorsUseThePaginatedEndpointWithAKey(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/pulses/693096c1cabeccbc6b3a5def": pulseDetailBody,
		"/pulses/693096c1cabeccbc6b3a5def/indicators": `{"count":1234,"next":"?page=2","previous":null,
		  "results":[{"id":1,"indicator":"paged.example","type":"domain","created":"2026-01-01T00:00:00","is_active":1}]}`,
	}))
	t.Setenv("OTX_LOOKUP_API_KEY", "k")

	code, out, errOut := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def", "--indicators")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "indicators: 1 of 1234") {
		t.Errorf("the exact count from the paginated endpoint was not used:\n%s", out)
	}
	if !strings.Contains(out, "paged.example") {
		t.Errorf("the paginated results were not listed:\n%s", out)
	}
}

// If the paginated endpoint fails, fall back to the embedded set rather than
// failing — but do not then claim the count is exact.
func TestPulseFallsBackToTheEmbeddedSet(t *testing.T) {
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.EscapedPath(), "/indicators") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"detail":"boom"}`))
			return
		}
		w.Write([]byte(pulseDetailBody))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "k")

	code, out, errOut := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def", "--indicators")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "microsoft-login.com") {
		t.Errorf("the embedded fallback was not used:\n%s", out)
	}
	if strings.Contains(out, " of ") {
		t.Errorf("an exact count was claimed after the paginated endpoint failed:\n%s", out)
	}
}

func TestPulseJSON(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/pulses/693096c1cabeccbc6b3a5def": pulseDetailBody,
	}))

	code, out, errOut := runCmd(t, "pulse", "--json", "--indicators", "693096c1cabeccbc6b3a5def")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	var res struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		IndicatorsHeld  int    `json:"indicators_held"`
		IndicatorsShown int    `json:"indicators_shown"`
		IndicatorsExact bool   `json:"indicators_exact"`
		AttackIDs       []string
		Indicators      []struct {
			Indicator string `json:"indicator"`
			IsActive  int    `json:"is_active"`
		} `json:"indicators"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if res.IndicatorsExact {
		t.Error("indicators_exact is true without the paginated endpoint")
	}
	if res.IndicatorsHeld != -1 {
		t.Errorf("indicators_held = %d, want -1 for unknown", res.IndicatorsHeld)
	}
	if res.IndicatorsShown != 2 || len(res.Indicators) != 2 {
		t.Errorf("shown = %d, indicators = %d", res.IndicatorsShown, len(res.Indicators))
	}
}

func TestPulseLimit(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/pulses/693096c1cabeccbc6b3a5def": pulseDetailBody,
	}))
	code, out, _ := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def", "--indicators", "--limit", "1")
	if code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, "retired.example") {
		t.Errorf("--limit did not cap the indicator list:\n%s", out)
	}
}

func TestPulseUnknownIdIsAnError(t *testing.T) {
	isolate(t, routes(nil)) // everything 404s
	code, _, errOut := runCmd(t, "pulse", "nosuchpulse")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut, "nosuchpulse") {
		t.Errorf("stderr does not name the pulse: %s", errOut)
	}
}

func TestPulseNeedsExactlyOneID(t *testing.T) {
	isolate(t, routes(nil))
	if code, _, _ := runCmd(t, "pulse"); code != exitError {
		t.Errorf("no id: exit = %d, want %d", code, exitError)
	}
	if code, _, _ := runCmd(t, "pulse", "a", "b"); code != exitError {
		t.Errorf("two ids: exit = %d, want %d", code, exitError)
	}
}

// Search needs a key, and must say so precisely without spending a request.
func TestSearchWithoutAKeyExplainsItself(t *testing.T) {
	requests := 0
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{}`))
	})

	code, _, errOut := runCmd(t, "search", "qakbot")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if requests != 0 {
		t.Errorf("%d request(s) spent on an endpoint known to need a key", requests)
	}
	if !strings.Contains(errOut, "OTX_LOOKUP_API_KEY") {
		t.Errorf("stderr does not say how to set a key: %s", errOut)
	}
}

func TestSearchWithAKey(t *testing.T) {
	isolate(t, routes(map[string]string{
		"/search/pulses": `{"count":2,"next":null,"previous":null,"results":[
		  {"id":"s1","name":"Qakbot campaign","modified":"2026-08-01T00:00:00.000000",
		   "author":{"username":"a"},"tags":["qakbot"],"indicator_count":10},
		  {"id":"s2","name":"Qakbot infrastructure","modified":"2026-07-01T00:00:00.000000",
		   "author":{"username":"b"},"indicator_count":5}]}`,
	}))
	t.Setenv("OTX_LOOKUP_API_KEY", "k")

	code, out, errOut := runCmd(t, "search", "qakbot")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	for _, want := range []string{`"qakbot"`, "2 pulses held, 2 shown", "Qakbot campaign", "s1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// A multi-word query is one query, not several.
func TestSearchJoinsMultipleWords(t *testing.T) {
	var gotQuery string
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		w.Write([]byte(`{"count":0,"results":[]}`))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "k")

	if code, _, errOut := runCmd(t, "search", "salt", "typhoon"); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if gotQuery != "salt typhoon" {
		t.Errorf("query sent = %q, want %q", gotQuery, "salt typhoon")
	}
}

func TestSearchNeedsAQuery(t *testing.T) {
	isolate(t, routes(nil))
	if code, _, errOut := runCmd(t, "search"); code != exitError {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, exitError, errOut)
	}
}

func TestCacheStatusAndClear(t *testing.T) {
	isolate(t, routes(map[string]string{"/indicators/domain/evil.test/general": richBody}))

	if code, _, errOut := runCmd(t, "lookup", "evil.test"); code != exitOK {
		t.Fatalf("seed lookup failed: %s", errOut)
	}

	code, out, errOut := runCmd(t, "cache", "status")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "entries: 1") {
		t.Errorf("status does not report the seeded entry:\n%s", out)
	}
	if !strings.Contains(out, "ttl:") {
		t.Errorf("status does not report the TTL:\n%s", out)
	}

	code, out, errOut = runCmd(t, "cache", "clear")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if !strings.Contains(out, "removed 1 cached entry") {
		t.Errorf("clear did not report what it removed:\n%s", out)
	}

	_, out, _ = runCmd(t, "cache", "status")
	if !strings.Contains(out, "entries: 0") {
		t.Errorf("cache was not empty after clear:\n%s", out)
	}
}

func TestCacheStatusJSON(t *testing.T) {
	isolate(t, routes(nil))
	code, out, errOut := runCmd(t, "cache", "status", "--json")
	if code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	var st struct {
		Dir      string  `json:"dir"`
		Entries  int     `json:"entries"`
		TTLHours float64 `json:"ttl_hours"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if st.TTLHours != 24 {
		t.Errorf("ttl_hours = %v, want 24", st.TTLHours)
	}
	if st.Dir == "" {
		t.Error("status does not report where the cache lives")
	}
}

func TestCacheRejectsUnknownSubcommand(t *testing.T) {
	isolate(t, routes(nil))
	code, _, errOut := runCmd(t, "cache", "purge")
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
	if !strings.Contains(errOut, "purge") {
		t.Errorf("stderr does not name the bad subcommand: %s", errOut)
	}
}

// --anonymous applies to every command, not only lookup.
func TestAnonymousAppliesToPulse(t *testing.T) {
	var sawKey string
	isolate(t, func(w http.ResponseWriter, r *http.Request) {
		sawKey = r.Header.Get("X-OTX-API-KEY")
		w.Write([]byte(pulseDetailBody))
	})
	t.Setenv("OTX_LOOKUP_API_KEY", "secret-key")

	if code, _, errOut := runCmd(t, "pulse", "693096c1cabeccbc6b3a5def", "--anonymous"); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut)
	}
	if sawKey != "" {
		t.Errorf("--anonymous still sent a key: %q", sawKey)
	}
}
