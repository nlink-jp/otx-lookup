package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// PulseFetcher is the pulse and search surface, kept separate from Fetcher so a
// test can stub one without the other.
type PulseFetcher interface {
	PulseDetail(ctx context.Context, id string) (*otx.PulseDetail, error)
	PulseIndicatorPage(ctx context.Context, id string, page, limit int) (*otx.IndicatorPage, error)
	Search(ctx context.Context, query string, page, limit int) (*otx.SearchResults, error)
}

// PulseResult is one pulse, with the indicators it carries.
type PulseResult struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Author      string    `json:"author"`
	Created     time.Time `json:"created,omitzero"`
	Modified    time.Time `json:"modified,omitzero"`
	TLP         string    `json:"tlp,omitempty"`
	Revision    int       `json:"revision"`

	Adversary         string   `json:"adversary,omitempty"`
	MalwareFamilies   []string `json:"malware_families,omitempty"`
	AttackIDs         []string `json:"attack_ids,omitempty"`
	Industries        []string `json:"industries,omitempty"`
	TargetedCountries []string `json:"targeted_countries,omitempty"`
	Tags              []string `json:"tags,omitempty"`
	References        []string `json:"references,omitempty"`

	Indicators []otx.PulseIndicator `json:"indicators,omitempty"`

	// IndicatorsHeld is what upstream says the pulse contains, and is only
	// known when the paginated endpoint answered — the detail response carries
	// no total at all. -1 means "unknown".
	IndicatorsHeld  int  `json:"indicators_held"`
	IndicatorsShown int  `json:"indicators_shown"`
	IndicatorsExact bool `json:"indicators_exact"`

	Cached   bool            `json:"cached"`
	Requests int             `json:"requests"`
	Raw      json.RawMessage `json:"-"`
}

// PulseOptions control a pulse fetch.
type PulseOptions struct {
	Indicators bool // list the indicators the pulse carries
	Limit      int  // maximum indicators to return; 0 means all that were fetched
	Refresh    bool // bypass the cache
}

// Pulse fetches one pulse.
//
// The detail endpoint answers anonymously and embeds an `indicators` array, so
// the pivot from a pulse to its other indicators works without a key. What it
// does not carry is a total: there is no count and no pagination cursor, so an
// embedded set that stopped early is indistinguishable from a complete one. The
// result therefore reports IndicatorsExact=false unless the paginated endpoint —
// which does return a count, and does need a key — was used.
func (e *Engine) Pulse(ctx context.Context, id string, opts PulseOptions) (*PulseResult, error) {
	if id == "" {
		return nil, fmt.Errorf("empty pulse id")
	}
	pf, ok := e.Fetcher.(PulseFetcher)
	if !ok {
		return nil, fmt.Errorf("this engine has no pulse support")
	}

	key := cache.Key("pulse", id, cache.AuthScope(e.Fetcher.HasKey()))
	var detail *otx.PulseDetail
	cached := false
	if !opts.Refresh && e.Cache != nil {
		if raw, hit := e.Cache.Get(key, e.now(), e.Cfg.CacheTTL); hit {
			var p otx.PulseDetail
			if err := json.Unmarshal(raw, &p); err == nil {
				p.Raw = raw
				detail, cached = &p, true
			}
		}
	}
	if detail == nil {
		p, err := pf.PulseDetail(ctx, id)
		if err != nil {
			return nil, err
		}
		detail = p
		if e.Cache != nil {
			_ = e.Cache.Put(key, p.Raw, e.now())
		}
	}

	res := &PulseResult{
		ID:                detail.ID,
		Name:              detail.Name,
		Description:       detail.Description,
		Author:            firstNonEmpty(detail.Author.Username, detail.AuthorName),
		TLP:               detail.TLP,
		Revision:          detail.Revision,
		Adversary:         detail.Adversary,
		MalwareFamilies:   namedLabels(detail.MalwareFamilies),
		AttackIDs:         attackLabels(detail.AttackIDs),
		Industries:        detail.Industries,
		TargetedCountries: detail.TargetedCountries,
		Tags:              detail.Tags,
		References:        detail.References,
		IndicatorsHeld:    -1,
		Cached:            cached,
		Raw:               detail.Raw,
	}
	if t, ok := detail.CreatedAt(); ok {
		res.Created = t
	}
	if t, ok := detail.ModifiedAt(); ok {
		res.Modified = t
	}

	if opts.Indicators {
		if err := e.fillIndicators(ctx, pf, res, detail, id, opts); err != nil {
			return nil, err
		}
	}
	res.Requests = e.Fetcher.Requests()
	return res, nil
}

// fillIndicators prefers the paginated endpoint when a key is available,
// because only that one reports how many indicators the pulse actually holds.
// Without a key it falls back to the set embedded in the detail, and says so by
// leaving IndicatorsExact false.
func (e *Engine) fillIndicators(ctx context.Context, pf PulseFetcher, res *PulseResult, detail *otx.PulseDetail, id string, opts PulseOptions) error {
	if e.Fetcher.HasKey() {
		page, err := pf.PulseIndicatorPage(ctx, id, 1, opts.Limit)
		if err == nil {
			res.Indicators = page.Results
			res.IndicatorsHeld = page.Count
			res.IndicatorsExact = true
			res.IndicatorsShown = len(res.Indicators)
			return nil
		}
		// Fall through to the embedded set rather than failing: a usable
		// partial answer beats no answer, and IndicatorsExact stays false.
		res.Indicators = detail.Indicators
	} else {
		res.Indicators = detail.Indicators
	}

	if opts.Limit > 0 && len(res.Indicators) > opts.Limit {
		res.Indicators = res.Indicators[:opts.Limit]
	}
	res.IndicatorsShown = len(res.Indicators)
	return nil
}

// SearchResult is one page of pulse search results.
type SearchResult struct {
	Query   string         `json:"query"`
	Held    int            `json:"held"`
	Shown   int            `json:"shown"`
	HasMore bool           `json:"has_more"`
	Pulses  []PulseSummary `json:"pulses"`

	Requests int             `json:"requests"`
	Raw      json.RawMessage `json:"-"`
}

// Search runs a pulse search. It requires an API key; the client refuses before
// spending a request when there is none.
func (e *Engine) Search(ctx context.Context, query string, page, limit int) (*SearchResult, error) {
	pf, ok := e.Fetcher.(PulseFetcher)
	if !ok {
		return nil, fmt.Errorf("this engine has no search support")
	}
	if limit <= 0 {
		limit = e.Cfg.DefaultLimit
	}
	if page <= 0 {
		page = 1
	}

	// Search results are not cached. A search is a question about what exists
	// right now, and a stale answer to "has anyone reported this yet" is worse
	// than a slow one.
	results, err := pf.Search(ctx, query, page, limit)
	if err != nil {
		return nil, err
	}

	res := &SearchResult{
		Query:    query,
		Held:     results.Count,
		HasMore:  results.Next != nil && *results.Next != "",
		Requests: e.Fetcher.Requests(),
		Raw:      results.Raw,
	}
	for _, p := range results.Results {
		res.Pulses = append(res.Pulses, summarize(p))
	}
	res.Shown = len(res.Pulses)
	return res, nil
}

func namedLabels(refs []otx.NamedRef) []string { return labels(refs) }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
