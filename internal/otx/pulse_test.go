package otx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The pulse detail as measured live: indicators embedded, numeric id,
// is_active 0/1, expiration null, timestamps without fractional seconds on the
// indicator records but with them on the pulse.
const liveShapedDetail = `{
  "id":"693096c1cabeccbc6b3a5def","name":"Phishing Domain Patterns",
  "author":{"username":"reporter","id":"42"},"author_name":"reporter",
  "created":"2025-12-03T20:00:01.385000","modified":"2026-08-01T10:00:00.000000",
  "TLP":"white","public":1,"revision":3,"in_group":false,"is_subscribing":null,
  "adversary":"APT-X",
  "malware_families":[{"id":"Qakbot","display_name":"Qakbot","target":null}],
  "attack_ids":[{"id":"T1041","name":"Exfil","display_name":"T1041 - Exfil"}],
  "industries":[],"targeted_countries":[],"tags":["phishing"],
  "references":["https://example.test/r"],
  "indicators":[{"id":4157203540,"indicator":"microsoft-login.com","type":"domain",
    "created":"2025-12-03T20:00:02","content":"","title":"",
    "description":"Microsoft phishing pattern","expiration":null,"is_active":1}]}`

func TestPulseDetailDecodesTheLiveShape(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(liveShapedDetail))
	})

	p, err := c.PulseDetail(context.Background(), "693096c1cabeccbc6b3a5def")
	if err != nil {
		t.Fatalf("PulseDetail: %v", err)
	}
	if p.Name != "Phishing Domain Patterns" || p.Revision != 3 || p.TLP != "white" {
		t.Errorf("detail = %+v", p)
	}
	if p.Author.Username != "reporter" {
		t.Errorf("author = %+v", p.Author)
	}
	if len(p.Indicators) != 1 {
		t.Fatalf("indicators = %d, want 1", len(p.Indicators))
	}
	ind := p.Indicators[0]
	if ind.ID != 4157203540 || ind.Indicator != "microsoft-login.com" {
		t.Errorf("indicator = %+v", ind)
	}
	if !ind.Active() {
		t.Error("is_active=1 did not read as active")
	}
	if ind.Expiration != nil {
		t.Errorf("a null expiration decoded as %v", *ind.Expiration)
	}
	// The indicator timestamp has no fractional seconds; it must still parse.
	if got, ok := ParseTime(ind.Created); !ok || got.Year() != 2025 {
		t.Errorf("indicator timestamp did not parse: %q", ind.Created)
	}
	if len(p.Raw) == 0 {
		t.Error("Raw was not preserved")
	}
}

// The same field appears as an object in one representation; a bare string in
// the other must not fail the decode. Neither form is invented — the object
// form was measured, and the detail's own arrays have only been seen empty.
func TestNamedRefAndAttackIDAcceptBothForms(t *testing.T) {
	body := `{"id":"p","malware_families":["Qakbot"],"attack_ids":["T1041"],"indicators":[]}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })

	p, err := c.PulseDetail(context.Background(), "p")
	if err != nil {
		t.Fatalf("bare-string form failed to decode: %v", err)
	}
	if len(p.MalwareFamilies) != 1 || p.MalwareFamilies[0].Label() != "Qakbot" {
		t.Errorf("malware_families = %+v", p.MalwareFamilies)
	}
	if len(p.AttackIDs) != 1 || p.AttackIDs[0].Label() != "T1041" {
		t.Errorf("attack_ids = %+v", p.AttackIDs)
	}
}

func TestPulseIndicatorPageRequiresAKeyAndDecodes(t *testing.T) {
	body := `{"count":4090,"next":"?page=2","previous":null,
	  "results":[{"id":1,"indicator":"a.test","type":"domain","created":"2026-01-01T00:00:00","is_active":1}]}`

	// Without a key: refused before a request.
	requests := 0
	anon, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(body))
	})
	if _, err := anon.PulseIndicatorPage(context.Background(), "p", 1, 10); Code(err) != CodeAuthRequired {
		t.Errorf("code = %q, want %q", Code(err), CodeAuthRequired)
	}
	if requests != 0 {
		t.Errorf("%d request(s) spent without a key", requests)
	}

	// With a key: decoded, including the count that makes a total exact.
	srv := newKeyedServer(t, body)
	keyed := New(srv, "k", time.Second, 0, "ua")
	page, err := keyed.PulseIndicatorPage(context.Background(), "p", 1, 10)
	if err != nil {
		t.Fatalf("PulseIndicatorPage: %v", err)
	}
	if page.Count != 4090 || len(page.Results) != 1 {
		t.Errorf("page = %+v", page)
	}
	if page.Next == nil || *page.Next != "?page=2" {
		t.Errorf("next = %v", page.Next)
	}
}

func TestSearchDecodes(t *testing.T) {
	body := `{"count":2,"exact_match":"","next":null,"previous":null,"results":[
	  {"id":"s1","name":"One","modified":"2026-08-01T00:00:00.000000","author":{"username":"a"}},
	  {"id":"s2","name":"Two","modified":"2026-07-01T00:00:00.000000","author":{"username":"b"}}]}`
	srv := newKeyedServer(t, body)
	c := New(srv, "k", time.Second, 0, "ua")

	res, err := c.Search(context.Background(), "qakbot", 1, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Count != 2 || len(res.Results) != 2 {
		t.Errorf("results = %+v", res)
	}
	if res.Next != nil {
		t.Errorf("a null next decoded as %v", *res.Next)
	}
	if res.Results[0].Author.Username != "a" {
		t.Errorf("author = %+v", res.Results[0].Author)
	}
}

// exact_match is documented as a boolean and arrives as a string. Declaring it
// bool made the entire search fail to decode, which reached a live run. Whatever
// type it takes, search must keep working.
func TestSearchSurvivesAnyExactMatchType(t *testing.T) {
	for _, em := range []string{`""`, `"some pulse"`, `true`, `false`, `null`, `0`} {
		body := `{"count":1,"exact_match":` + em + `,"next":null,"previous":null,"results":[{"id":"s1","name":"One"}]}`
		srv := newKeyedServer(t, body)
		c := New(srv, "k", time.Second, 0, "ua")

		res, err := c.Search(context.Background(), "q", 1, 10)
		if err != nil {
			t.Errorf("exact_match=%s broke the search decode: %v", em, err)
			continue
		}
		if res.Count != 1 || len(res.Results) != 1 {
			t.Errorf("exact_match=%s: results = %+v", em, res)
		}
	}
}

func TestDecodeErrorsAreReported(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"indicators": "not an array"}`))
	})
	if _, err := c.PulseDetail(context.Background(), "p"); Code(err) != CodeDecode {
		t.Errorf("code = %q, want %q (err: %v)", Code(err), CodeDecode, err)
	}
}

// A gateway error arrives as an HTML page. Pasting markup into the operator's
// terminal explains nothing the status code did not already say.
func TestHTMLErrorBodyIsNotEchoed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
		w.Write([]byte("<html>\n<head><title>504 Gateway Time-out</title></head>\n</html>"))
	})
	_, err := c.Pulse(context.Background(), "p")
	if err == nil {
		t.Fatal("want an error")
	}
	if got := err.Error(); strings.Contains(got, "<html>") || strings.Contains(got, "<title>") {
		t.Errorf("HTML leaked into the error message: %q", got)
	}
	if Code(err) != CodeUpstream {
		t.Errorf("code = %q, want %q", Code(err), CodeUpstream)
	}
}

// newKeyedServer serves one body, and 403s a request that arrives without the
// key header — the same boundary the live API enforces.
func newKeyedServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") == "" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"detail":"forbidden"}`))
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRawIsValidJSONOnEveryDecodedType(t *testing.T) {
	srv := newKeyedServer(t, `{"count":0,"results":[]}`)
	c := New(srv, "k", time.Second, 0, "ua")
	res, err := c.Search(context.Background(), "q", 1, 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if !json.Valid(res.Raw) {
		t.Error("SearchResults.Raw is not valid JSON")
	}
}
