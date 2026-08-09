package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/indicator"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// Fetcher is the upstream surface the engine depends on, so tests inject a stub
// instead of a server.
type Fetcher interface {
	General(ctx context.Context, typ, value string) (*otx.General, error)
	IndicatorSection(ctx context.Context, typ, value, section string) (json.RawMessage, error)
	HasKey() bool
	Requests() int
}

// Engine is the shared core behind the CLI and the MCP server. Both go through
// it so the two faces cannot give different answers for the same indicator.
type Engine struct {
	Cfg     *config.Config
	Cache   *cache.Store
	Fetcher Fetcher
	Now     func() time.Time
}

// New builds an engine with the real clock.
func New(cfg *config.Config, store *cache.Store, f Fetcher) *Engine {
	return &Engine{Cfg: cfg, Cache: store, Fetcher: f, Now: time.Now}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Options control one lookup.
type Options struct {
	Sections []string // extra sections beyond general
	Limit    int      // pulses to list; 0 uses the configured default
	Refresh  bool     // bypass the cache and re-query
}

// Counted is a context value with the number of pulses that named it. The count
// is what separates a campaign the whole community reports from one analyst's
// guess, so it is never dropped.
type Counted struct {
	Value  string `json:"value"`
	Pulses int    `json:"pulses"`
}

// Context is the aggregate campaign picture across every pulse that named the
// indicator — the answer no sibling tool can give.
type Context struct {
	Adversaries       []Counted `json:"adversaries,omitempty"`
	MalwareFamilies   []Counted `json:"malware_families,omitempty"`
	AttackIDs         []Counted `json:"attack_ids,omitempty"`
	Industries        []Counted `json:"industries,omitempty"`
	TargetedCountries []Counted `json:"targeted_countries,omitempty"`
	Tags              []Counted `json:"tags,omitempty"`
	FirstReported     time.Time `json:"first_reported,omitzero"`
	LastReported      time.Time `json:"last_reported,omitzero"`
}

// Empty reports whether no pulse carried any context at all.
func (c Context) Empty() bool {
	return len(c.Adversaries) == 0 && len(c.MalwareFamilies) == 0 && len(c.AttackIDs) == 0 &&
		len(c.Industries) == 0 && len(c.TargetedCountries) == 0 && len(c.Tags) == 0
}

// PulseSummary is one community report, reduced to what an analyst weighs.
type PulseSummary struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Author          string    `json:"author"`
	Created         time.Time `json:"created,omitzero"`
	Modified        time.Time `json:"modified,omitzero"`
	TLP             string    `json:"tlp,omitempty"`
	IndicatorCount  int       `json:"indicator_count"`
	Adversary       string    `json:"adversary,omitempty"`
	MalwareFamilies []string  `json:"malware_families,omitempty"`
	AttackIDs       []string  `json:"attack_ids,omitempty"`
	Tags            []string  `json:"tags,omitempty"`
	Upvotes         int       `json:"upvotes"`
	Downvotes       int       `json:"downvotes"`
}

// Result is one indicator's answer.
type Result struct {
	Query     string `json:"query"`
	Type      string `json:"type"`      // the OTX type that answered
	Indicator string `json:"indicator"` // as OTX echoes it back

	// TriedTypes records every type queried. A name is asked as both `domain`
	// and `hostname` when the first returns nothing, and which one answered is
	// part of the answer.
	TriedTypes []string `json:"tried_types,omitempty"`

	// PulsesHeld is what upstream reported and PulsesShown is what was listed.
	// Held is a lower bound — OTX returns exactly 50 for heavily-reported
	// indicators, which is a page size, not a total. Both are always emitted so
	// a partial answer can never read as a complete one.
	PulsesHeld  int  `json:"pulses_held"`
	PulsesShown int  `json:"pulses_shown"`
	Capped      bool `json:"capped"`

	Pulses  []PulseSummary `json:"pulses,omitempty"`
	Context Context        `json:"context"`

	References           []string         `json:"references,omitempty"`
	Validation           []otx.Validation `json:"validation,omitempty"`
	FalsePositiveReports int              `json:"false_positive_reports"`

	// Sections holds the extra sections asked for with --sections, verbatim.
	Sections map[string]json.RawMessage `json:"sections,omitempty"`

	// Degraded names what could not be fetched.
	Degraded []string `json:"degraded,omitempty"`

	// Incomplete marks that one of the indicator types could not be queried at
	// all. It matters most when PulsesHeld is zero: "nothing reported this" and
	// "we could not ask" look identical in the data and mean opposite things.
	// A caller must not read an incomplete empty result as a clean indicator.
	Incomplete bool `json:"incomplete"`

	Cached   bool            `json:"cached"`
	Requests int             `json:"requests"`
	Raw      json.RawMessage `json:"-"`
}

// HasPulses reports whether any community report named the indicator.
func (r *Result) HasPulses() bool { return r.PulsesHeld > 0 || len(r.Pulses) > 0 }

// EmptyButUnverified reports an answer of "no pulses" that must not be read as
// a clean indicator, because one of the types could not be queried.
func (r *Result) EmptyButUnverified() bool { return !r.HasPulses() && r.Incomplete }

// Lookup answers one target.
//
// Finding nothing is a successful answer: most indicators an analyst types have
// never been reported by anyone, and that is worth knowing.
func (e *Engine) Lookup(ctx context.Context, target string, opts Options) (*Result, error) {
	ind, err := indicator.Classify(target)
	if err != nil {
		return nil, err
	}
	if err := e.validateSections(ind, opts.Sections); err != nil {
		return nil, err
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = e.Cfg.DefaultLimit
	}

	res := &Result{Query: target}
	var firstErr error
	var general *otx.General
	var chosen indicator.Type

	// Ask the shape-derived type first, then the alternate when it reported
	// nothing. OTX indexes a name's pulses under exactly one of `domain` or
	// `hostname` and answers 200 either way, so without this second attempt a
	// wrong guess is indistinguishable from a clean indicator.
	for _, t := range ind.Types() {
		res.TriedTypes = append(res.TriedTypes, string(t))
		g, cached, err := e.general(ctx, ind, t, opts.Refresh)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// Record it rather than swallowing it. If the other type then
			// answers with zero pulses, an unrecorded failure would be
			// presented as "nothing reported this indicator" — a false
			// negative produced by a transient upstream error, which is the
			// single worst way this tool can be wrong.
			res.Degraded = append(res.Degraded, fmt.Sprintf("type %s: %v", t, err))
			res.Incomplete = true
			continue
		}
		res.Cached = res.Cached || cached
		if general == nil || g.PulseInfo.Count > general.PulseInfo.Count {
			general, chosen = g, t
		}
		if g.PulseInfo.Count > 0 {
			break
		}
	}
	if general == nil {
		return nil, firstErr
	}

	e.fill(res, general, chosen, limit)
	e.fetchExtraSections(ctx, res, ind, chosen, opts)
	res.Requests = e.Fetcher.Requests()
	return res, nil
}

// validateSections rejects a section the type does not have before spending a
// round trip on a request that cannot succeed.
func (e *Engine) validateSections(ind indicator.Indicator, sections []string) error {
	for _, s := range sections {
		if s == "general" {
			continue // always fetched; asking for it explicitly is harmless
		}
		ok := false
		for _, t := range ind.Types() {
			if indicator.HasSection(t, s) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("OTX has no %q section for %s; available: %s",
				s, ind.Type, strings.Join(indicator.Sections(ind.Type), ", "))
		}
	}
	return nil
}

// general fetches one type's general section, through the cache.
func (e *Engine) general(ctx context.Context, ind indicator.Indicator, t indicator.Type, refresh bool) (*otx.General, bool, error) {
	key := e.cacheKey("general", string(t), ind.Value, "general")
	if !refresh && e.Cache != nil {
		if raw, ok := e.Cache.Get(key, e.now(), e.Cfg.CacheTTL); ok {
			var g otx.General
			if err := json.Unmarshal(raw, &g); err == nil {
				g.Raw = raw
				return &g, true, nil
			}
		}
	}
	g, err := e.Fetcher.General(ctx, string(t), ind.Value)
	if err != nil {
		return nil, false, err
	}
	if e.Cache != nil {
		_ = e.Cache.Put(key, g.Raw, e.now()) // a cache write failure must not fail a lookup
	}
	return g, false, nil
}

func (e *Engine) cacheKey(kind, typ, value, section string) string {
	return cache.Key(kind, typ, value, section, cache.AuthScope(e.Fetcher.HasKey()))
}

// fetchExtraSections retrieves the sections asked for with --sections. A
// section that fails is recorded in Degraded rather than failing the lookup:
// the campaign context is the answer, and a missing side dish must not throw it
// away.
func (e *Engine) fetchExtraSections(ctx context.Context, res *Result, ind indicator.Indicator, t indicator.Type, opts Options) {
	for _, s := range opts.Sections {
		if s == "general" {
			continue
		}
		if !indicator.HasSection(t, s) {
			continue // validated already; the answering type simply lacks it
		}
		key := e.cacheKey("section", string(t), ind.Value, s)
		if !opts.Refresh && e.Cache != nil {
			if raw, ok := e.Cache.Get(key, e.now(), e.Cfg.CacheTTL); ok {
				res.addSection(s, raw)
				continue
			}
		}
		raw, err := e.Fetcher.IndicatorSection(ctx, string(t), ind.Value, s)
		if err != nil {
			res.Degraded = append(res.Degraded, fmt.Sprintf("%s: %v", s, err))
			continue
		}
		if e.Cache != nil {
			_ = e.Cache.Put(key, raw, e.now())
		}
		res.addSection(s, raw)
	}
}

func (r *Result) addSection(name string, raw json.RawMessage) {
	if r.Sections == nil {
		r.Sections = map[string]json.RawMessage{}
	}
	r.Sections[name] = raw
}

// fill reduces a general response into the result.
func (e *Engine) fill(res *Result, g *otx.General, t indicator.Type, limit int) {
	res.Type = string(t)
	res.Indicator = g.Indicator
	res.Raw = g.Raw
	res.References = g.PulseInfo.References
	res.Validation = g.Validation
	res.FalsePositiveReports = len(g.FalsePositive)
	res.PulsesHeld = g.PulseInfo.Count

	pulses := append([]otx.Pulse(nil), g.PulseInfo.Pulses...)
	sort.SliceStable(pulses, func(i, j int) bool {
		ti, _ := pulses[i].ModifiedAt()
		tj, _ := pulses[j].ModifiedAt()
		if ti.Equal(tj) {
			return pulses[i].Name < pulses[j].Name
		}
		return ti.After(tj)
	})

	res.Context = aggregate(pulses)

	shown := pulses
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
		res.Capped = true
	}
	for _, p := range shown {
		res.Pulses = append(res.Pulses, summarize(p))
	}
	res.PulsesShown = len(res.Pulses)

	// Upstream returned fewer pulses than it says it holds — the page cap.
	if res.PulsesHeld > len(pulses) {
		res.Capped = true
	}
}

func summarize(p otx.Pulse) PulseSummary {
	s := PulseSummary{
		ID:             p.ID,
		Name:           p.Name,
		Author:         p.Author.Username,
		TLP:            p.TLP,
		IndicatorCount: p.IndicatorCount,
		Adversary:      p.Adversary,
		Tags:           p.Tags,
		Upvotes:        p.UpvotesCount,
		Downvotes:      p.DownvotesCount,
	}
	if t, ok := p.CreatedAt(); ok {
		s.Created = t
	}
	if t, ok := p.ModifiedAt(); ok {
		s.Modified = t
	}
	for _, m := range p.MalwareFamilies {
		if l := m.Label(); l != "" {
			s.MalwareFamilies = append(s.MalwareFamilies, l)
		}
	}
	for _, a := range p.AttackIDs {
		if l := a.Label(); l != "" {
			s.AttackIDs = append(s.AttackIDs, l)
		}
	}
	return s
}

// aggregate counts how many pulses named each value, and finds the reporting
// window. Counting by pulse rather than by occurrence is what makes the number
// mean "how many independent reports agree".
func aggregate(pulses []otx.Pulse) Context {
	adversaries := map[string]int{}
	families := map[string]int{}
	attacks := map[string]int{}
	industries := map[string]int{}
	countries := map[string]int{}
	tags := map[string]int{}
	var first, last time.Time

	for _, p := range pulses {
		if v := strings.TrimSpace(p.Adversary); v != "" {
			adversaries[v]++
		}
		countUnique(families, labels(p.MalwareFamilies))
		countUnique(attacks, attackLabels(p.AttackIDs))
		countUnique(industries, p.Industries)
		countUnique(countries, p.TargetedCountries)
		countUnique(tags, p.Tags)

		if t, ok := p.CreatedAt(); ok {
			if first.IsZero() || t.Before(first) {
				first = t
			}
		}
		if t, ok := p.ModifiedAt(); ok {
			if last.IsZero() || t.After(last) {
				last = t
			}
		}
	}

	return Context{
		Adversaries:       rank(adversaries),
		MalwareFamilies:   rank(families),
		AttackIDs:         rank(attacks),
		Industries:        rank(industries),
		TargetedCountries: rank(countries),
		Tags:              rank(tags),
		FirstReported:     first,
		LastReported:      last,
	}
}

func labels(refs []otx.NamedRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if l := r.Label(); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func attackLabels(ids []otx.AttackID) []string {
	out := make([]string, 0, len(ids))
	for _, a := range ids {
		if l := a.Label(); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// countUnique credits one pulse with at most one vote per value, so a pulse
// that lists the same tag twice does not look like two reports.
func countUnique(into map[string]int, values []string) {
	seen := map[string]bool{}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		into[v]++
	}
}

// rank orders by pulse count descending, then by value, so output is stable
// across runs.
func rank(m map[string]int) []Counted {
	if len(m) == 0 {
		return nil
	}
	out := make([]Counted, 0, len(m))
	for v, n := range m {
		out = append(out, Counted{Value: v, Pulses: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pulses != out[j].Pulses {
			return out[i].Pulses > out[j].Pulses
		}
		return out[i].Value < out[j].Value
	})
	return out
}
