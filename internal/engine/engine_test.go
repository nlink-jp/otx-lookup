package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// stub is an injected upstream. It records every call so a test can assert on
// what was asked, not only on what came back.
type stub struct {
	generals map[string]string // "type/value" -> JSON body
	sections map[string]string // "type/value/section" -> JSON body
	errs     map[string]error  // "type/value" -> error
	calls    []string
	keyed    bool
}

func (s *stub) General(_ context.Context, typ, value string) (*otx.General, error) {
	k := typ + "/" + value
	s.calls = append(s.calls, k)
	if err, ok := s.errs[k]; ok {
		return nil, err
	}
	body, ok := s.generals[k]
	if !ok {
		return nil, &otx.Error{Code: otx.CodeNotFound, Message: "no stub for " + k}
	}
	var g otx.General
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		return nil, err
	}
	g.Raw = json.RawMessage(body)
	return &g, nil
}

func (s *stub) IndicatorSection(_ context.Context, typ, value, section string) (json.RawMessage, error) {
	k := typ + "/" + value + "/" + section
	s.calls = append(s.calls, k)
	if err, ok := s.errs[k]; ok {
		return nil, err
	}
	body, ok := s.sections[k]
	if !ok {
		return nil, &otx.Error{Code: otx.CodeNotFound, Message: "no stub for " + k}
	}
	return json.RawMessage(body), nil
}

func (s *stub) HasKey() bool  { return s.keyed }
func (s *stub) Requests() int { return len(s.calls) }

func newEngine(t *testing.T, s *stub) *Engine {
	t.Helper()
	cfg := &config.Config{
		BaseURL:      config.DefaultBaseURL,
		DefaultLimit: 10,
		CacheTTL:     time.Hour,
		MCPInlineMax: 200,
	}
	e := New(cfg, &cache.Store{Dir: t.TempDir()}, s)
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return e
}

func general(count int, pulses ...string) string {
	return fmt.Sprintf(`{"indicator":"x","type":"domain","pulse_info":{"count":%d,"pulses":[%s]}}`,
		count, strings.Join(pulses, ","))
}

func pulse(id, name, modified string, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"id":%q,"name":%q,"modified":%q,"created":%q,"author":{"username":"rep"}%s}`,
		id, name, modified, modified, extra)
}

// The core behaviour, on the case that motivated it. bbc.co.uk has three
// labels, so the shape puts `hostname` first — but it is a registrable domain
// and OTX indexes its pulses under `domain` (measured 2026-08-09: hostname 0,
// domain 22). Both answer 200, so without the second attempt the wrong guess is
// indistinguishable from a clean indicator.
func TestNameFallsBackToTheAlternateType(t *testing.T) {
	s := &stub{generals: map[string]string{
		"hostname/bbc.co.uk": general(0),
		"domain/bbc.co.uk":   general(2, pulse("p1", "Campaign", "2026-08-01T00:00:00.000000", "")),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "bbc.co.uk", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "domain" {
		t.Errorf("answered as %q, want domain (the fallback)", res.Type)
	}
	if res.PulsesHeld != 2 {
		t.Errorf("PulsesHeld = %d, want 2", res.PulsesHeld)
	}
	if len(res.TriedTypes) != 2 || res.TriedTypes[0] != "hostname" || res.TriedTypes[1] != "domain" {
		t.Errorf("TriedTypes = %v, want [hostname domain]", res.TriedTypes)
	}
}

// The mirror case: when the shape-derived type answers, there is no second
// request to make.
func TestPrimaryHitSkipsTheAlternate(t *testing.T) {
	s := &stub{generals: map[string]string{
		"hostname/www.example.com": general(2, pulse("p1", "Campaign", "2026-08-01T00:00:00.000000", "")),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "www.example.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "hostname" {
		t.Errorf("answered as %q, want hostname", res.Type)
	}
	if len(res.TriedTypes) != 1 {
		t.Errorf("TriedTypes = %v, want just the primary", res.TriedTypes)
	}
	if len(s.calls) != 1 {
		t.Errorf("made %d requests (%v), want 1", len(s.calls), s.calls)
	}
}

// The reverse case: a two-label name leads with `domain`, and when that answers
// there must be no second request.
func TestPrimaryHitCostsOneRequest(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/paypal.com": general(3, pulse("p1", "Phish", "2026-08-01T00:00:00.000000", "")),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "paypal.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "domain" {
		t.Errorf("answered as %q, want domain", res.Type)
	}
	if len(s.calls) != 1 {
		t.Errorf("made %d requests (%v), want 1", len(s.calls), s.calls)
	}
}

// Zero pulses everywhere is a real answer, not a failure — most indicators an
// analyst types have never been reported.
func TestNoPulsesIsASuccessfulAnswer(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/quiet.example":   general(0),
		"hostname/quiet.example": general(0),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "quiet.example", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.HasPulses() {
		t.Error("reported pulses where there are none")
	}
	if len(s.calls) != 2 {
		t.Errorf("made %d requests, want 2 (both types tried before concluding nothing)", len(s.calls))
	}
}

// An IP has exactly one type, so there is nothing to fall back to.
func TestSingleTypeIndicatorsTryOnce(t *testing.T) {
	s := &stub{generals: map[string]string{"IPv4/8.8.8.8": general(0)}}
	e := newEngine(t, s)
	if _, err := e.Lookup(context.Background(), "8.8.8.8", Options{}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(s.calls) != 1 {
		t.Errorf("made %d requests (%v), want 1", len(s.calls), s.calls)
	}
}

func TestAggregatesCampaignContextWithPulseCounts(t *testing.T) {
	attack := `"attack_ids":[{"id":"T1041","name":"Exfil","display_name":"T1041 - Exfil"}]`
	fam := `"malware_families":[{"id":"Qakbot","display_name":"Qakbot"}]`
	s := &stub{generals: map[string]string{
		"domain/evil.test": general(3,
			pulse("p1", "A", "2026-08-01T00:00:00.000000", `"adversary":"APT-X",`+fam+`,`+attack+`,"industries":["Finance"],"tags":["c2","c2"]`),
			pulse("p2", "B", "2026-07-01T00:00:00.000000", `"adversary":"APT-X",`+fam+`,"targeted_countries":["Japan"]`),
			pulse("p3", "C", "2026-06-01T00:00:00.000000", `"tags":["phishing"]`),
		),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "evil.test", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	c := res.Context
	if len(c.Adversaries) != 1 || c.Adversaries[0].Value != "APT-X" || c.Adversaries[0].Pulses != 2 {
		t.Errorf("adversaries = %+v, want APT-X reported by 2 pulses", c.Adversaries)
	}
	if len(c.MalwareFamilies) != 1 || c.MalwareFamilies[0].Pulses != 2 {
		t.Errorf("malware_families = %+v", c.MalwareFamilies)
	}
	if len(c.AttackIDs) != 1 || c.AttackIDs[0].Value != "T1041 - Exfil" {
		t.Errorf("attack_ids = %+v", c.AttackIDs)
	}
	if len(c.Industries) != 1 || c.Industries[0].Value != "Finance" {
		t.Errorf("industries = %+v", c.Industries)
	}
	if len(c.TargetedCountries) != 1 || c.TargetedCountries[0].Value != "Japan" {
		t.Errorf("targeted_countries = %+v", c.TargetedCountries)
	}
	// A pulse listing the same tag twice is still one report.
	for _, tag := range c.Tags {
		if tag.Value == "c2" && tag.Pulses != 1 {
			t.Errorf("tag c2 counted %d times within one pulse", tag.Pulses)
		}
	}
	if c.FirstReported.IsZero() || c.LastReported.IsZero() {
		t.Error("the reporting window was not derived")
	}
	if !c.FirstReported.Before(c.LastReported) {
		t.Errorf("window is inverted: %v .. %v", c.FirstReported, c.LastReported)
	}
}

// Ordering must be deterministic: by pulse count, then by value.
func TestContextRankingIsStable(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/evil.test": general(3,
			pulse("p1", "A", "2026-08-01T00:00:00.000000", `"tags":["beta","alpha"]`),
			pulse("p2", "B", "2026-07-01T00:00:00.000000", `"tags":["alpha"]`),
			pulse("p3", "C", "2026-06-01T00:00:00.000000", `"tags":["gamma"]`),
		),
	}}
	e := newEngine(t, s)
	res, err := e.Lookup(context.Background(), "evil.test", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	got := make([]string, 0, len(res.Context.Tags))
	for _, c := range res.Context.Tags {
		got = append(got, fmt.Sprintf("%s=%d", c.Value, c.Pulses))
	}
	want := "alpha=2 beta=1 gamma=1"
	if strings.Join(got, " ") != want {
		t.Errorf("tags = %q, want %q", strings.Join(got, " "), want)
	}
}

// Pulses are listed newest first, because "is this still active" is the first
// question an analyst has.
func TestPulsesSortedNewestFirst(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/evil.test": general(3,
			pulse("old", "Old", "2026-01-01T00:00:00.000000", ""),
			pulse("new", "New", "2026-08-01T00:00:00.000000", ""),
			pulse("mid", "Mid", "2026-04-01T00:00:00.000000", ""),
		),
	}}
	e := newEngine(t, s)
	res, err := e.Lookup(context.Background(), "evil.test", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Pulses) != 3 {
		t.Fatalf("got %d pulses", len(res.Pulses))
	}
	if res.Pulses[0].ID != "new" || res.Pulses[2].ID != "old" {
		t.Errorf("order = %s,%s,%s", res.Pulses[0].ID, res.Pulses[1].ID, res.Pulses[2].ID)
	}
}

// The honesty rule: what upstream holds is always reported next to what was
// retrieved, and any shortfall is marked.
func TestHeldVersusShownIsAlwaysReported(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/evil.test": general(3,
			pulse("p1", "A", "2026-08-01T00:00:00.000000", ""),
			pulse("p2", "B", "2026-07-01T00:00:00.000000", ""),
			pulse("p3", "C", "2026-06-01T00:00:00.000000", ""),
		),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "evil.test", Options{Limit: 2})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.PulsesHeld != 3 || res.PulsesShown != 2 {
		t.Errorf("held/shown = %d/%d, want 3/2", res.PulsesHeld, res.PulsesShown)
	}
	if !res.Capped {
		t.Error("a truncated list was not marked as capped")
	}
}

// Upstream's count exceeding the pulses it actually returned is the page cap.
// That must be visible even when the analyst asked for no limit at all.
func TestUpstreamPageCapIsMarked(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/evil.test": general(50, pulse("p1", "A", "2026-08-01T00:00:00.000000", "")),
	}}
	e := newEngine(t, s)
	res, err := e.Lookup(context.Background(), "evil.test", Options{Limit: 100})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !res.Capped {
		t.Error("held(50) > returned(1) must be marked as capped")
	}
}

func TestCacheAvoidsASecondRequest(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/paypal.com": general(1, pulse("p1", "A", "2026-08-01T00:00:00.000000", "")),
	}}
	e := newEngine(t, s)

	if _, err := e.Lookup(context.Background(), "paypal.com", Options{}); err != nil {
		t.Fatalf("first Lookup: %v", err)
	}
	res, err := e.Lookup(context.Background(), "paypal.com", Options{})
	if err != nil {
		t.Fatalf("second Lookup: %v", err)
	}
	if !res.Cached {
		t.Error("second lookup did not report a cache hit")
	}
	if len(s.calls) != 1 {
		t.Errorf("made %d upstream calls, want 1", len(s.calls))
	}

	// --refresh must go back upstream.
	if _, err := e.Lookup(context.Background(), "paypal.com", Options{Refresh: true}); err != nil {
		t.Fatalf("refresh Lookup: %v", err)
	}
	if len(s.calls) != 2 {
		t.Errorf("--refresh made %d calls, want 2", len(s.calls))
	}
}

// A keyed answer and an anonymous one carry different per-account fields, so
// they must not share a cache slot.
func TestCacheIsScopedToAuth(t *testing.T) {
	body := general(1, pulse("p1", "A", "2026-08-01T00:00:00.000000", ""))
	anonStub := &stub{generals: map[string]string{"domain/paypal.com": body}}
	dir := t.TempDir()

	cfg := &config.Config{BaseURL: config.DefaultBaseURL, DefaultLimit: 10, CacheTTL: time.Hour, MCPInlineMax: 200}
	anon := New(cfg, &cache.Store{Dir: dir}, anonStub)
	anon.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	if _, err := anon.Lookup(context.Background(), "paypal.com", Options{}); err != nil {
		t.Fatalf("anonymous Lookup: %v", err)
	}

	keyedStub := &stub{generals: map[string]string{"domain/paypal.com": body}, keyed: true}
	keyed := New(cfg, &cache.Store{Dir: dir}, keyedStub)
	keyed.Now = anon.Now
	res, err := keyed.Lookup(context.Background(), "paypal.com", Options{})
	if err != nil {
		t.Fatalf("keyed Lookup: %v", err)
	}
	if res.Cached {
		t.Error("a keyed lookup was served from the anonymous cache entry")
	}
}

// Extra sections are opt-in and stored verbatim.
func TestExtraSectionsFetchedOnRequest(t *testing.T) {
	s := &stub{
		generals: map[string]string{"IPv4/8.8.8.8": general(0)},
		sections: map[string]string{"IPv4/8.8.8.8/reputation": `{"reputation":0}`},
	}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "8.8.8.8", Options{Sections: []string{"reputation"}})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, ok := res.Sections["reputation"]; !ok {
		t.Fatalf("reputation section missing: %v", res.Sections)
	}
	if string(res.Sections["reputation"]) != `{"reputation":0}` {
		t.Errorf("section body was altered: %s", res.Sections["reputation"])
	}

	// Nothing extra is fetched by default — that is what keeps the tool from
	// duplicating its siblings.
	s2 := &stub{generals: map[string]string{"IPv4/8.8.8.8": general(0)}}
	e2 := newEngine(t, s2)
	if _, err := e2.Lookup(context.Background(), "8.8.8.8", Options{}); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	for _, c := range s2.calls {
		if strings.Contains(c, "/reputation") || strings.Contains(c, "/passive_dns") {
			t.Errorf("an overlapping section was fetched by default: %s", c)
		}
	}
}

// A section the type does not have is rejected before any request.
func TestUnknownSectionRejectedBeforeRequesting(t *testing.T) {
	s := &stub{generals: map[string]string{"IPv4/8.8.8.8": general(0)}}
	e := newEngine(t, s)

	_, err := e.Lookup(context.Background(), "8.8.8.8", Options{Sections: []string{"whois"}})
	if err == nil {
		t.Fatal("want an error: IPv4 has no whois section")
	}
	if !strings.Contains(err.Error(), "whois") {
		t.Errorf("error does not name the section: %v", err)
	}
	if len(s.calls) != 0 {
		t.Errorf("spent %d request(s) on a section that cannot exist", len(s.calls))
	}
}

// A failed side section degrades the result; it does not throw away the
// campaign context, which is the actual answer.
func TestFailedSectionDegradesRatherThanFails(t *testing.T) {
	s := &stub{
		generals: map[string]string{"IPv4/8.8.8.8": general(1, pulse("p1", "A", "2026-08-01T00:00:00.000000", ""))},
		errs:     map[string]error{"IPv4/8.8.8.8/reputation": &otx.Error{Code: otx.CodeUpstream, Message: "boom"}},
	}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "8.8.8.8", Options{Sections: []string{"reputation"}})
	if err != nil {
		t.Fatalf("a failing side section must not fail the lookup: %v", err)
	}
	if len(res.Degraded) != 1 || !strings.Contains(res.Degraded[0], "reputation") {
		t.Errorf("Degraded = %v, want the reputation failure recorded", res.Degraded)
	}
	if !res.HasPulses() {
		t.Error("the campaign context was thrown away with the failed section")
	}
}

// A malformed target never reaches upstream.
func TestInvalidTargetIsRejectedBeforeAnyRequest(t *testing.T) {
	s := &stub{}
	e := newEngine(t, s)
	if _, err := e.Lookup(context.Background(), "not a target", Options{}); err == nil {
		t.Fatal("want a classification error")
	}
	if len(s.calls) != 0 {
		t.Errorf("spent %d request(s) on an invalid target", len(s.calls))
	}
}

// When every type errors, the lookup fails with the first error rather than
// pretending the indicator is clean.
func TestAllTypesFailingIsAnError(t *testing.T) {
	s := &stub{errs: map[string]error{
		"domain/paypal.com":   &otx.Error{Code: otx.CodeUpstream, Message: "first failure"},
		"hostname/paypal.com": &otx.Error{Code: otx.CodeUpstream, Message: "second failure"},
	}}
	e := newEngine(t, s)

	_, err := e.Lookup(context.Background(), "paypal.com", Options{})
	if err == nil {
		t.Fatal("want an error when nothing could be fetched")
	}
	if !strings.Contains(err.Error(), "first failure") {
		t.Errorf("error = %v, want the first failure surfaced", err)
	}
}

// The worst failure this tool can produce: one type errors, the other answers
// with zero pulses, and the result reads as "nothing reported this indicator".
// A transient upstream error must never be laundered into a clean verdict.
func TestFailedTypeMakesAnEmptyResultInconclusive(t *testing.T) {
	s := &stub{
		generals: map[string]string{"hostname/paypal.com": general(0)},
		errs:     map[string]error{"domain/paypal.com": &otx.Error{Code: otx.CodeRateLimited, Message: "429"}},
	}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "paypal.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.HasPulses() {
		t.Fatal("fixture error: this result should have no pulses")
	}
	if !res.Incomplete {
		t.Error("a failed type did not mark the result incomplete")
	}
	if !res.EmptyButUnverified() {
		t.Error("an empty result built on a failed lookup was reported as conclusive")
	}
	if len(res.Degraded) != 1 || !strings.Contains(res.Degraded[0], "domain") {
		t.Errorf("Degraded = %v, want the failed type named", res.Degraded)
	}
}

// The mirror: when every type answered, an empty result is conclusive and must
// not be hedged.
func TestCleanEmptyResultIsConclusive(t *testing.T) {
	s := &stub{generals: map[string]string{
		"domain/quiet.example":   general(0),
		"hostname/quiet.example": general(0),
	}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "quiet.example", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Incomplete || res.EmptyButUnverified() {
		t.Error("a fully-answered empty result was marked inconclusive")
	}
	if len(res.Degraded) != 0 {
		t.Errorf("Degraded = %v, want empty", res.Degraded)
	}
}

// One type failing while the other answers is still a usable answer.
func TestPartialTypeFailureStillAnswers(t *testing.T) {
	s := &stub{
		generals: map[string]string{"hostname/www.example.com": general(1, pulse("p1", "A", "2026-08-01T00:00:00.000000", ""))},
		errs:     map[string]error{"domain/www.example.com": &otx.Error{Code: otx.CodeUpstream, Message: "boom"}},
	}
	e := newEngine(t, s)
	res, err := e.Lookup(context.Background(), "www.example.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "hostname" || !res.HasPulses() {
		t.Errorf("result = %+v", res)
	}
}

// Validation and false-positive reports are evidence the analyst weighs, so
// they must survive into the result rather than being silently dropped.
func TestValidationAndFalsePositivesSurvive(t *testing.T) {
	body := `{"indicator":"paypal.com","type":"domain",
	  "validation":[{"source":"whitelist","message":"Whitelisted domain","name":"Whitelisted"}],
	  "false_positive":[{"assessment":"benign"}],
	  "pulse_info":{"count":1,"references":["https://example.test/r"],"pulses":[
	    {"id":"p1","name":"A","modified":"2026-08-01T00:00:00.000000","author":{"username":"rep"}}]}}`
	s := &stub{generals: map[string]string{"domain/paypal.com": body}}
	e := newEngine(t, s)

	res, err := e.Lookup(context.Background(), "paypal.com", Options{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(res.Validation) != 1 || res.Validation[0].Name != "Whitelisted" {
		t.Errorf("validation = %+v", res.Validation)
	}
	if res.FalsePositiveReports != 1 {
		t.Errorf("FalsePositiveReports = %d, want 1", res.FalsePositiveReports)
	}
	if len(res.References) != 1 {
		t.Errorf("references = %v", res.References)
	}
}
