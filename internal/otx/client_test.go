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

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "", 5*time.Second, 0, "otx-lookup/test")
	return c, srv
}

func TestIndicatorSectionPathAndEscaping(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
		t.Fatalf("IndicatorSection: %v", err)
	}
	if gotPath != "/indicators/domain/example.com/general" {
		t.Errorf("path = %q", gotPath)
	}

	// A URL indicator's own slashes must not become path separators.
	if _, err := c.IndicatorSection(context.Background(), "url", "https://evil.test/a/b", "general"); err != nil {
		t.Fatalf("IndicatorSection: %v", err)
	}
	if strings.Count(gotPath, "/") != 4 {
		t.Errorf("URL indicator leaked path separators: %q", gotPath)
	}
	if !strings.Contains(gotPath, "%2F") {
		t.Errorf("URL indicator was not escaped: %q", gotPath)
	}
}

// The key goes in the header and nowhere else. A key in the query string would
// reach proxy logs, referrer headers and shell history.
func TestAPIKeyTravelsOnlyInTheHeader(t *testing.T) {
	var gotHeader, gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-OTX-API-KEY")
		gotRawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	keyed := New(srv.URL, "secret-key", time.Second, 0, "ua")
	if _, err := keyed.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
		t.Fatalf("IndicatorSection: %v", err)
	}
	if gotHeader != "secret-key" {
		t.Errorf("X-OTX-API-KEY = %q, want the configured key", gotHeader)
	}
	if strings.Contains(gotRawQuery, "secret-key") {
		t.Errorf("key leaked into the query string: %q", gotRawQuery)
	}

	anon := New(srv.URL, "", time.Second, 0, "ua")
	if _, err := anon.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
		t.Fatalf("IndicatorSection: %v", err)
	}
	if gotHeader != "" {
		t.Errorf("anonymous client sent X-OTX-API-KEY = %q", gotHeader)
	}
}

// Decoding must survive the real response shapes: attack_ids and
// malware_families are arrays of objects, industries and targeted_countries are
// arrays of strings, and timestamps carry no zone.
func TestGeneralDecodesMeasuredShapes(t *testing.T) {
	body := `{
	  "indicator": "paypal.com",
	  "type": "domain",
	  "sections": ["general","geo","url_list"],
	  "validation": [{"source":"whitelist","message":"Whitelisted domain","name":"Whitelisted"}],
	  "false_positive": [],
	  "pulse_info": {
	    "count": 2,
	    "references": ["https://example.test/report"],
	    "pulses": [{
	      "id": "abc123",
	      "name": "Phishing campaign",
	      "author": {"username": "reporter", "id": "42"},
	      "created": "2026-03-23T00:25:09.116000",
	      "modified": "2026-08-09T14:35:39.341000",
	      "TLP": "green",
	      "public": 1,
	      "adversary": "Unknown APT Group(s)",
	      "malware_families": [{"id":"Fakeav","display_name":"Fakeav","target":null}],
	      "attack_ids": [{"id":"T1041","name":"Exfiltration Over C2 Channel","display_name":"T1041 - Exfiltration Over C2 Channel"}],
	      "industries": ["Education","Healthcare"],
	      "targeted_countries": ["Canada"],
	      "tags": ["phishing","scam"],
	      "indicator_count": 334995,
	      "indicator_type_counts": {"domain": 204754, "hostname": 130241}
	    }]
	  }
	}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })

	g, err := c.General(context.Background(), "domain", "paypal.com")
	if err != nil {
		t.Fatalf("General: %v", err)
	}
	if g.Indicator != "paypal.com" || g.Type != "domain" {
		t.Errorf("indicator/type = %q/%q", g.Indicator, g.Type)
	}
	if len(g.Validation) != 1 || g.Validation[0].Source != "whitelist" {
		t.Errorf("validation = %+v", g.Validation)
	}
	if g.PulseInfo.Count != 2 || len(g.PulseInfo.Pulses) != 1 {
		t.Fatalf("pulse_info count=%d pulses=%d", g.PulseInfo.Count, len(g.PulseInfo.Pulses))
	}

	p := g.PulseInfo.Pulses[0]
	if p.Author.Username != "reporter" {
		t.Errorf("author = %+v", p.Author)
	}
	if len(p.MalwareFamilies) != 1 || p.MalwareFamilies[0].Label() != "Fakeav" {
		t.Errorf("malware_families = %+v", p.MalwareFamilies)
	}
	if len(p.AttackIDs) != 1 || p.AttackIDs[0].ID != "T1041" {
		t.Errorf("attack_ids = %+v", p.AttackIDs)
	}
	if p.AttackIDs[0].Label() != "T1041 - Exfiltration Over C2 Channel" {
		t.Errorf("attack label = %q", p.AttackIDs[0].Label())
	}
	if len(p.Industries) != 2 || p.Industries[0] != "Education" {
		t.Errorf("industries = %v", p.Industries)
	}
	if p.IndicatorTypeCounts["hostname"] != 130241 {
		t.Errorf("indicator_type_counts = %v", p.IndicatorTypeCounts)
	}
	created, ok := p.CreatedAt()
	if !ok {
		t.Fatal("created timestamp did not parse")
	}
	if created.Location() != time.UTC {
		t.Errorf("timestamp parsed in %v, want UTC — a zoneless value read as local shifts every timeline", created.Location())
	}
	if created.Year() != 2026 || created.Month() != time.March || created.Day() != 23 {
		t.Errorf("created = %v", created)
	}
	if len(g.Raw) == 0 {
		t.Error("Raw body was not preserved for --json")
	}
}

// A pulse with a malformed date must still be usable; only that field is lost.
func TestParseTime(t *testing.T) {
	if _, ok := ParseTime("2026-03-23T00:25:09.116000"); !ok {
		t.Error("the measured OTX layout did not parse")
	}
	if got, ok := ParseTime("2026-03-23T00:25:09Z"); !ok || got.Year() != 2026 {
		t.Error("RFC 3339 should also be accepted")
	}
	if _, ok := ParseTime(""); ok {
		t.Error("empty string reported as a valid time")
	}
	if _, ok := ParseTime("not a date"); ok {
		t.Error("garbage reported as a valid time")
	}
}

func TestStatusMapping(t *testing.T) {
	tests := []struct {
		status   int
		body     string
		wantCode string
	}{
		{http.StatusBadRequest, `{"detail":"bad indicator"}`, CodeBadRequest},
		{http.StatusForbidden, `{"detail":"forbidden"}`, CodeAuthRequired},
		{http.StatusUnauthorized, `{}`, CodeAuthRequired},
		{http.StatusNotFound, `{}`, CodeNotFound},
		{http.StatusTooManyRequests, `{}`, CodeRateLimited},
		{http.StatusInternalServerError, `{}`, CodeUpstream},
		{http.StatusBadGateway, `{}`, CodeUpstream},
	}
	for _, tc := range tests {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})
		_, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general")
		if err == nil {
			t.Errorf("status %d: want an error", tc.status)
			continue
		}
		if got := Code(err); got != tc.wantCode {
			t.Errorf("status %d: code = %q, want %q", tc.status, got, tc.wantCode)
		}
	}
}

// Upstream's own words are more useful than a bare status number.
func TestUpstreamMessageIsSurfaced(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"Invalid IPv4 address"}`))
	})
	_, err := c.IndicatorSection(context.Background(), "IPv4", "not-an-ip", "general")
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "Invalid IPv4 address") {
		t.Errorf("upstream detail was dropped: %q", err)
	}
}

func TestNonJSONBodyIsADecodeError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>maintenance</html>"))
	})
	_, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general")
	if got := Code(err); got != CodeDecode {
		t.Errorf("code = %q, want %q (err: %v)", got, CodeDecode, err)
	}
}

// The three key-only endpoints must fail before spending a request: the
// boundary is known, and a wasted round trip costs quota and tells OTX about
// the query anyway.
func TestKeyOnlyEndpointsFailWithoutARequest(t *testing.T) {
	requests := 0
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := c.PulseIndicators(context.Background(), "abc", 1, 10); Code(err) != CodeAuthRequired {
		t.Errorf("PulseIndicators without a key: code = %q, want %q", Code(err), CodeAuthRequired)
	}
	if _, err := c.SearchPulses(context.Background(), "qakbot", 1, 10); Code(err) != CodeAuthRequired {
		t.Errorf("SearchPulses without a key: code = %q, want %q", Code(err), CodeAuthRequired)
	}
	if requests != 0 {
		t.Errorf("%d request(s) sent for endpoints known to need a key", requests)
	}

	// The message has to tell the operator what still works without a key.
	_, err := c.SearchPulses(context.Background(), "q", 0, 0)
	if !strings.Contains(err.Error(), "OTX_LOOKUP_API_KEY") {
		t.Errorf("error does not say how to set a key: %q", err)
	}
}

// Pulse detail and related answer anonymously — the counterpart of the check
// above, and the reason the key is optional at all.
func TestPulseDetailWorksAnonymously(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"abc"}`))
	})
	if _, err := c.Pulse(context.Background(), "abc"); err != nil {
		t.Errorf("Pulse without a key: %v", err)
	}
	if _, err := c.PulseRelated(context.Background(), "abc"); err != nil {
		t.Errorf("PulseRelated without a key: %v", err)
	}
}

func TestPagingParameters(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Encode()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "key", time.Second, 0, "ua")

	if _, err := c.SearchPulses(context.Background(), "qak bot", 2, 25); err != nil {
		t.Fatalf("SearchPulses: %v", err)
	}
	for _, want := range []string{"q=qak+bot", "page=2", "limit=25"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q is missing %q", gotQuery, want)
		}
	}
}

// Upstream sorts search results oldest-first by default, which puts 2015
// reports at the top of a "qakbot" search. Newest-first has to be requested.
func TestSearchAsksForNewestFirst(t *testing.T) {
	var gotSort string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSort = r.URL.Query().Get("sort")
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "key", time.Second, 0, "ua")

	if _, err := c.SearchPulses(context.Background(), "qakbot", 1, 10); err != nil {
		t.Fatalf("SearchPulses: %v", err)
	}
	if gotSort != SearchSort {
		t.Errorf("sort = %q, want %q — upstream's default is oldest-first", gotSort, SearchSort)
	}
}

// OTX returns no rate-budget header, so the ceiling is enforced locally. With a
// budget of two per window, the third request must wait for the first to age
// out.
func TestLimiterPacesAgainstTheLocalCeiling(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	c.limiter = &limiter{max: 2, window: time.Hour}

	now := time.Unix(1_700_000_000, 0)
	var slept []time.Duration
	c.Now = func() time.Time { return now }
	c.Sleep = func(d time.Duration) {
		slept = append(slept, d)
		now = now.Add(d)
	}

	for i := 0; i < 3; i++ {
		if _, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if len(slept) != 1 {
		t.Fatalf("slept %d times, want 1 (the third request should wait)", len(slept))
	}
	if slept[0] != time.Hour {
		t.Errorf("waited %v, want the full window", slept[0])
	}
}

func TestLimiterDisabledWhenBudgetIsZero(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	c.Sleep = func(d time.Duration) { t.Fatalf("slept %v with no budget configured", d) }
	for i := 0; i < 5; i++ {
		if _, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
}

func TestRequestsCounter(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	c.limiter = &limiter{max: 100, window: time.Hour}
	for i := 0; i < 3; i++ {
		if _, err := c.IndicatorSection(context.Background(), "domain", "example.com", "general"); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := c.Requests(); got != 3 {
		t.Errorf("Requests() = %d, want 3", got)
	}
}

func TestContextCancellationIsANetworkError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.IndicatorSection(ctx, "domain", "example.com", "general")
	if got := Code(err); got != CodeNetwork {
		t.Errorf("code = %q, want %q (err: %v)", got, CodeNetwork, err)
	}
}

func TestNamedRefLabelFallsBackToID(t *testing.T) {
	if got := (NamedRef{ID: "Fakeav"}).Label(); got != "Fakeav" {
		t.Errorf("Label() = %q", got)
	}
	if got := (AttackID{ID: "T1041", Name: "Exfil"}).Label(); got != "T1041 - Exfil" {
		t.Errorf("Label() = %q", got)
	}
	if got := (AttackID{ID: "T1041"}).Label(); got != "T1041" {
		t.Errorf("Label() = %q", got)
	}
}

func TestRawMessagePreservedForUnknownFields(t *testing.T) {
	// A CVE response has a completely different top-level shape. Decoding must
	// not fail, and the body must survive for --json.
	body := `{"indicator":"CVE-2021-44228","cvss":{"Score":9.3},"epss":0.97,"exploits":[],"pulse_info":{"count":0,"pulses":[]}}`
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	g, err := c.General(context.Background(), "cve", "CVE-2021-44228")
	if err != nil {
		t.Fatalf("General: %v", err)
	}
	var round map[string]json.RawMessage
	if err := json.Unmarshal(g.Raw, &round); err != nil {
		t.Fatalf("Raw is not valid JSON: %v", err)
	}
	if _, ok := round["cvss"]; !ok {
		t.Error("Raw dropped a type-specific field")
	}
}
