package engine

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// pulseStub adds the pulse and search surface to the lookup stub.
type pulseStub struct {
	stub
	detail    *otx.PulseDetail
	page      *otx.IndicatorPage
	results   *otx.SearchResults
	detailErr error
	pageErr   error
	searchErr error
	pageCalls int
}

func (p *pulseStub) PulseDetail(_ context.Context, id string) (*otx.PulseDetail, error) {
	p.calls = append(p.calls, "pulse/"+id)
	return p.detail, p.detailErr
}

func (p *pulseStub) PulseIndicatorPage(_ context.Context, id string, page, limit int) (*otx.IndicatorPage, error) {
	p.pageCalls++
	p.calls = append(p.calls, "pulse/"+id+"/indicators")
	return p.page, p.pageErr
}

func (p *pulseStub) Search(_ context.Context, query string, page, limit int) (*otx.SearchResults, error) {
	p.calls = append(p.calls, "search/"+query)
	return p.results, p.searchErr
}

func sampleDetail() *otx.PulseDetail {
	return &otx.PulseDetail{
		ID: "p1", Name: "Campaign", Author: otx.Author{Username: "reporter"},
		Created: "2026-01-01T00:00:00.000000", Modified: "2026-08-01T00:00:00.000000",
		TLP: "green", Revision: 2,
		Adversary:       "APT-X",
		MalwareFamilies: []otx.NamedRef{{ID: "Qakbot", DisplayName: "Qakbot"}},
		AttackIDs:       []otx.AttackID{{ID: "T1041", DisplayName: "T1041 - Exfil"}},
		Tags:            []string{"c2"},
		Indicators: []otx.PulseIndicator{
			{ID: 1, Indicator: "a.test", Type: "domain", IsActive: 1},
			{ID: 2, Indicator: "b.test", Type: "domain", IsActive: 0},
		},
		Raw: json.RawMessage(`{"id":"p1"}`),
	}
}

// Without a key the embedded set is used, and the total is explicitly unknown.
// Claiming a total the endpoint never reported would be an invention.
func TestPulseWithoutAKeyReportsAnUnknownTotal(t *testing.T) {
	ps := &pulseStub{detail: sampleDetail()}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Pulse(context.Background(), "p1", PulseOptions{Indicators: true})
	if err != nil {
		t.Fatalf("Pulse: %v", err)
	}
	if res.IndicatorsExact {
		t.Error("IndicatorsExact is true without the paginated endpoint")
	}
	if res.IndicatorsHeld != -1 {
		t.Errorf("IndicatorsHeld = %d, want -1 (unknown)", res.IndicatorsHeld)
	}
	if res.IndicatorsShown != 2 {
		t.Errorf("IndicatorsShown = %d, want 2", res.IndicatorsShown)
	}
	if ps.pageCalls != 0 {
		t.Error("the key-only endpoint was called without a key")
	}
	if res.Adversary != "APT-X" || len(res.AttackIDs) != 1 || res.AttackIDs[0] != "T1041 - Exfil" {
		t.Errorf("campaign metadata was lost: %+v", res)
	}
}

// With a key the paginated endpoint answers and the total becomes exact.
func TestPulseWithAKeyUsesThePaginatedEndpoint(t *testing.T) {
	ps := &pulseStub{
		detail: sampleDetail(),
		page: &otx.IndicatorPage{Count: 4090, Results: []otx.PulseIndicator{
			{ID: 9, Indicator: "paged.test", Type: "domain", IsActive: 1},
		}},
	}
	ps.keyed = true
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Pulse(context.Background(), "p1", PulseOptions{Indicators: true})
	if err != nil {
		t.Fatalf("Pulse: %v", err)
	}
	if !res.IndicatorsExact || res.IndicatorsHeld != 4090 {
		t.Errorf("exact=%v held=%d, want true/4090", res.IndicatorsExact, res.IndicatorsHeld)
	}
	if len(res.Indicators) != 1 || res.Indicators[0].Indicator != "paged.test" {
		t.Errorf("the paginated results were not used: %+v", res.Indicators)
	}
}

// If the paginated endpoint fails, fall back to the embedded set — but the
// total stays unknown, because it is.
func TestPulseFallsBackWithoutClaimingExactness(t *testing.T) {
	ps := &pulseStub{
		detail:  sampleDetail(),
		pageErr: &otx.Error{Code: otx.CodeUpstream, Message: "boom"},
	}
	ps.keyed = true
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Pulse(context.Background(), "p1", PulseOptions{Indicators: true})
	if err != nil {
		t.Fatalf("a failed page must not fail the pulse: %v", err)
	}
	if res.IndicatorsExact {
		t.Error("exactness was claimed after the paginated endpoint failed")
	}
	if len(res.Indicators) != 2 {
		t.Errorf("the embedded fallback was not used: %d indicators", len(res.Indicators))
	}
}

func TestPulseWithoutIndicatorsSkipsThem(t *testing.T) {
	ps := &pulseStub{detail: sampleDetail()}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Pulse(context.Background(), "p1", PulseOptions{})
	if err != nil {
		t.Fatalf("Pulse: %v", err)
	}
	if len(res.Indicators) != 0 {
		t.Errorf("indicators were fetched without being asked for: %d", len(res.Indicators))
	}
}

func TestPulseLimitCaps(t *testing.T) {
	ps := &pulseStub{detail: sampleDetail()}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Pulse(context.Background(), "p1", PulseOptions{Indicators: true, Limit: 1})
	if err != nil {
		t.Fatalf("Pulse: %v", err)
	}
	if len(res.Indicators) != 1 {
		t.Errorf("Limit was ignored: %d indicators", len(res.Indicators))
	}
}

func TestPulseIsCached(t *testing.T) {
	ps := &pulseStub{detail: sampleDetail()}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	if _, err := e.Pulse(context.Background(), "p1", PulseOptions{}); err != nil {
		t.Fatalf("first: %v", err)
	}
	res, err := e.Pulse(context.Background(), "p1", PulseOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !res.Cached {
		t.Error("the second fetch did not report a cache hit")
	}
	if _, err := e.Pulse(context.Background(), "p1", PulseOptions{Refresh: true}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Two upstream detail fetches: the first and the refresh.
	n := 0
	for _, c := range ps.calls {
		if c == "pulse/p1" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d upstream detail fetches, want 2 (first + refresh)", n)
	}
}

func TestPulseRejectsAnEmptyID(t *testing.T) {
	ps := &pulseStub{detail: sampleDetail()}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps
	if _, err := e.Pulse(context.Background(), "", PulseOptions{}); err == nil {
		t.Error("an empty pulse id was accepted")
	}
}

func TestSearchSummarisesResults(t *testing.T) {
	next := "?page=2"
	ps := &pulseStub{results: &otx.SearchResults{
		Count: 42, Next: &next,
		Results: []otx.Pulse{
			{ID: "s1", Name: "One", Modified: "2026-08-01T00:00:00.000000", Author: otx.Author{Username: "a"}},
			{ID: "s2", Name: "Two", Modified: "2026-07-01T00:00:00.000000", Author: otx.Author{Username: "b"}},
		},
	}}
	ps.keyed = true
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	res, err := e.Search(context.Background(), "qakbot", 0, 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Held != 42 || res.Shown != 2 {
		t.Errorf("held/shown = %d/%d, want 42/2", res.Held, res.Shown)
	}
	if !res.HasMore {
		t.Error("HasMore was not derived from the next cursor")
	}
	if res.Pulses[0].ID != "s1" || res.Pulses[0].Author != "a" {
		t.Errorf("results were not summarised: %+v", res.Pulses[0])
	}
}

// A search is a question about what exists right now, so it must not be served
// from a cache.
func TestSearchIsNotCached(t *testing.T) {
	ps := &pulseStub{results: &otx.SearchResults{Count: 1, Results: []otx.Pulse{{ID: "s1"}}}}
	ps.keyed = true
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	for i := 0; i < 2; i++ {
		if _, err := e.Search(context.Background(), "qakbot", 1, 5); err != nil {
			t.Fatalf("Search %d: %v", i, err)
		}
	}
	n := 0
	for _, c := range ps.calls {
		if c == "search/qakbot" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d upstream searches for two calls, want 2 — results were cached", n)
	}
}

func TestSearchPropagatesTheAuthError(t *testing.T) {
	ps := &pulseStub{searchErr: &otx.Error{Code: otx.CodeAuthRequired, Message: "needs a key"}}
	e := newEngine(t, &ps.stub)
	e.Fetcher = ps

	_, err := e.Search(context.Background(), "qakbot", 1, 5)
	if otx.Code(err) != otx.CodeAuthRequired {
		t.Errorf("code = %q, want %q", otx.Code(err), otx.CodeAuthRequired)
	}
}

// An engine whose fetcher has no pulse support must say so rather than panic.
func TestPulseAndSearchNeedAPulseFetcher(t *testing.T) {
	e := newEngine(t, &stub{})
	if _, err := e.Pulse(context.Background(), "p1", PulseOptions{}); err == nil {
		t.Error("Pulse succeeded without a pulse-capable fetcher")
	}
	if _, err := e.Search(context.Background(), "q", 1, 5); err == nil {
		t.Error("Search succeeded without a pulse-capable fetcher")
	}
}
