package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// Tool names. They are referenced by the embedded manual, and a meta-test pins
// the two together.
const (
	ToolLookupIndicator = "lookup_indicator"
	ToolGetPulse        = "get_pulse"
	ToolSearchPulses    = "search_pulses"
	ToolCacheStatus     = "cache_status"
	ToolGetUsage        = "get_usage"
)

// CodeInvalidArgument is this layer's own error code; the rest come from the
// otx package so an agent sees one vocabulary end to end.
const CodeInvalidArgument = "invalid_argument"

const instructions = `otx-lookup attaches campaign context to an indicator of compromise by reading ` +
	`the community reports ("pulses") of the LevelBlue Open Threat Exchange: which adversary, ` +
	`malware family, ATT&CK techniques, targeted industries and countries it was reported under, ` +
	`by whom, and when. Call get_usage first — it returns the full reference, the result schema, ` +
	`and the error-recovery table. Only a third-party index is read, so no packet reaches the ` +
	`target under investigation. An indicator with no pulses is a normal result, not an error. ` +
	`SOURCE QUALITY IS NOT UNIFORM, and this matters more than any other caveat here. Pulses are ` +
	`submitted by anyone: a curated incident write-up and an automated blocklist of 300,000 ` +
	`indicators arrive in the same shape, and every field holds whatever its author typed — ` +
	`adversary names that are pasted paragraphs, tags that are file hashes or analysis prose, ` +
	`references that are empty strings. Weigh the author, the vote counts and indicator_count ` +
	`before believing any of it, treat what several independent pulses agree on as far stronger ` +
	`than any single report, and never present a pulse hit as a malicious verdict — this server ` +
	`returns claims, not conclusions.`

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolLookupIndicator,
			"description": "Campaign context for one indicator (IPv4, IPv6, domain, hostname, URL, " +
				"MD5/SHA1/SHA256 hash, or CVE): the pulses that name it, plus aggregated adversaries, " +
				"malware families, ATT&CK techniques, targeted industries and countries. Finding no " +
				"pulses is a valid answer. The pulses behind it are community submissions of uneven " +
				"quality, so the aggregate mixes curated analysis with automated feed dumps and scraped " +
				"noise: read the `pulses` count on each value as its corroboration, and never treat a " +
				"hit as a verdict.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"indicator": map[string]any{
						"type":        "string",
						"description": "The indicator to look up. Its type is detected from its shape.",
					},
					"sections": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Extra sections to fetch beyond the default. Sections owned by a sibling tool (reputation, passive_dns, malware, analysis, url_list) are off by default.",
					},
					"limit":          map[string]any{"type": "integer", "description": "Pulses to list."},
					"anonymous":      map[string]any{"type": "boolean", "description": "Query without the configured API key, so the lookup is not recorded against the OTX account."},
					"refresh":        map[string]any{"type": "boolean", "description": "Bypass the result cache."},
					"context_top":    map[string]any{"type": "integer", "description": "Values kept per aggregate category, ranked by how many pulses named each (default 25). Raise it to see the least-corroborated tail; context_omitted counts what was dropped."},
					"references_top": map[string]any{"type": "integer", "description": "References kept (default 25). references_omitted counts what was dropped."},
				},
				"required": []string{"indicator"},
			},
		},
		{
			"name": ToolGetPulse,
			"description": "One pulse in full, optionally with the indicators it carries — the pivot " +
				"from a single indicator to the rest of a campaign. Works without an API key; a key " +
				"additionally yields the exact indicator total. Judge the pulse before trusting what it " +
				"carries: an `indicator_count` in the thousands means an automated feed dump rather than " +
				"an analysis, and the author, description and references tell you which one you have.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pulse_id":   map[string]any{"type": "string", "description": "The pulse id, as returned by lookup_indicator."},
					"indicators": map[string]any{"type": "boolean", "description": "Include the indicators the pulse carries."},
					"limit":      map[string]any{"type": "integer", "description": "Indicators per page. A feed-dump pulse holds thousands, so keep this small enough for your context."},
					"page":       map[string]any{"type": "integer", "description": "1-based indicator page (default 1). indicators_held is the total, so page through it rather than asking for everything at once."},
					"anonymous":  map[string]any{"type": "boolean", "description": "Query without the configured API key."},
					"refresh":    map[string]any{"type": "boolean", "description": "Bypass the result cache."},
				},
				"required": []string{"pulse_id"},
			},
		},
		{
			"name":        ToolSearchPulses,
			"description": "Search pulses by free text, newest first. Requires an OTX API key; without one this returns an auth_required error and spends no request. Results are whatever the community happened to name that way — a matching title is not evidence that the pulse concerns your case, or that it is any good.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":     map[string]any{"type": "string", "description": "Free-text query."},
					"limit":     map[string]any{"type": "integer", "description": "Results per page."},
					"page":      map[string]any{"type": "integer", "description": "Page number, from 1."},
					"anonymous": map[string]any{"type": "boolean", "description": "Query without the configured API key (this tool will then fail)."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        ToolCacheStatus,
			"description": "Where the result cache lives, how many entries it holds, and its TTL.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        ToolGetUsage,
			"description": "The full reference for this server: tools, arguments, result schema, and the error-recovery table. Call this first.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

func (s *Server) dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case ToolLookupIndicator:
		return s.lookupIndicator(ctx, args)
	case ToolGetPulse:
		return s.getPulse(ctx, args)
	case ToolSearchPulses:
		return s.searchPulses(ctx, args)
	case ToolCacheStatus:
		return s.cacheStatus()
	default:
		// get_usage never reaches here: it returns Markdown and is answered
		// before dispatch.
		return nil, argErrorf("unknown tool %q; call tools/list for the available tools", name)
	}
}

type lookupArgs struct {
	Indicator     string   `json:"indicator"`
	Sections      []string `json:"sections"`
	Limit         int      `json:"limit"`
	Anonymous     bool     `json:"anonymous"`
	Refresh       bool     `json:"refresh"`
	ContextTop    int      `json:"context_top"`
	ReferencesTop int      `json:"references_top"`
}

func (s *Server) lookupIndicator(ctx context.Context, raw json.RawMessage) (any, error) {
	var a lookupArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Indicator) == "" {
		return nil, argErrorf("indicator is required")
	}

	res, err := s.New(a.Anonymous).Lookup(ctx, a.Indicator, engine.Options{
		Sections: a.Sections,
		Limit:    a.Limit,
		Refresh:  a.Refresh,
	})
	if err != nil {
		return nil, err
	}
	return s.trimLookup(res, a), nil
}

// contextTopN bounds each aggregate category in a tool result, and
// referencesTopN bounds the reference list.
//
// `limit` caps the pulse list, but the aggregate and the references are
// independent of it and unbounded: a live `lookup_indicator` on
// CVE-2021-44228 with `limit: 3` produced a 162 KB result that no MCP client
// would accept — 63 KB of it 1,705 tags, most of them scraped noise from
// feed-dump pulses. The categories are ranked by how many pulses named each
// value, so the tail is the least-corroborated part and the first thing that
// should go. Every value dropped is counted in `context_omitted` /
// `references_omitted`, and `context_top` / `references_top` raise the cut on
// demand — the tool does not get to quietly shrink an answer, and nothing it
// holds back is unreachable.
const (
	contextTopN    = 25
	referencesTopN = 25
)

// topOr returns a caller-supplied cap, or the default when unset. A negative
// value means "no cap": an operator who wants the raw aggregate can say so.
func topOr(v, def int) int {
	if v < 0 {
		return -1
	}
	if v == 0 {
		return def
	}
	return v
}

// lookupPayload is what lookup_indicator returns. It embeds the engine result
// so the documented field names stay at the top level, and carries the
// accounting for anything trimmed alongside them.
type lookupPayload struct {
	*engine.Result
	ContextOmitted    map[string]int `json:"context_omitted,omitempty"`
	ReferencesOmitted int            `json:"references_omitted,omitempty"`
	Note              string         `json:"note,omitempty"`
}

func (s *Server) trimLookup(res *engine.Result, a lookupArgs) *lookupPayload {
	trimmed := *res
	out := &lookupPayload{Result: &trimmed}

	ctxTop := topOr(a.ContextTop, contextTopN)
	refTop := topOr(a.ReferencesTop, referencesTopN)

	omitted := map[string]int{}
	c := res.Context
	c.Adversaries, omitted["adversaries"] = trimCounted(res.Context.Adversaries, ctxTop)
	c.MalwareFamilies, omitted["malware_families"] = trimCounted(res.Context.MalwareFamilies, ctxTop)
	c.AttackIDs, omitted["attack_ids"] = trimCounted(res.Context.AttackIDs, ctxTop)
	c.Industries, omitted["industries"] = trimCounted(res.Context.Industries, ctxTop)
	c.TargetedCountries, omitted["targeted_countries"] = trimCounted(res.Context.TargetedCountries, ctxTop)
	c.Tags, omitted["tags"] = trimCounted(res.Context.Tags, ctxTop)
	trimmed.Context = c
	for k, n := range omitted {
		if n == 0 {
			delete(omitted, k)
		}
	}
	if len(omitted) > 0 {
		out.ContextOmitted = omitted
	}

	if refTop >= 0 && len(res.References) > refTop {
		trimmed.References = res.References[:refTop]
		out.ReferencesOmitted = len(res.References) - refTop
	}

	// The pulse list is bounded by the caller's own `limit`, so it is never
	// trimmed here: whatever was asked for is returned whole.
	if out.ContextOmitted == nil && out.ReferencesOmitted == 0 {
		return out
	}
	out.Note = trimNote(out, ctxTop)
	return out
}

func trimNote(out *lookupPayload, ctxTop int) string {
	parts := make([]string, 0, 2)
	if n := total(out.ContextOmitted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d aggregate values beyond the top %d per category were omitted "+
			"(they are the least-corroborated, one or two pulses each)", n, ctxTop))
	}
	if out.ReferencesOmitted > 0 {
		parts = append(parts, fmt.Sprintf("%d references were omitted", out.ReferencesOmitted))
	}
	return strings.Join(parts, "; ") + ". Raise context_top / references_top to see them."
}

func total(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// trimCounted keeps the top of an already-ranked category and reports how many
// were dropped.
func trimCounted(v []engine.Counted, top int) ([]engine.Counted, int) {
	if top < 0 || len(v) <= top {
		return v, 0
	}
	return v[:top], len(v) - top
}

type pulseArgs struct {
	PulseID    string `json:"pulse_id"`
	Indicators bool   `json:"indicators"`
	Limit      int    `json:"limit"`
	Page       int    `json:"page"`
	Anonymous  bool   `json:"anonymous"`
	Refresh    bool   `json:"refresh"`
}

func (s *Server) getPulse(ctx context.Context, raw json.RawMessage) (any, error) {
	var a pulseArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.PulseID) == "" {
		return nil, argErrorf("pulse_id is required")
	}

	res, err := s.New(a.Anonymous).Pulse(ctx, a.PulseID, engine.PulseOptions{
		Indicators: a.Indicators,
		Limit:      a.Limit,
		Page:       a.Page,
		Refresh:    a.Refresh,
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

type searchArgs struct {
	Query     string `json:"query"`
	Limit     int    `json:"limit"`
	Page      int    `json:"page"`
	Anonymous bool   `json:"anonymous"`
}

func (s *Server) searchPulses(ctx context.Context, raw json.RawMessage) (any, error) {
	var a searchArgs
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	if strings.TrimSpace(a.Query) == "" {
		return nil, argErrorf("query is required")
	}
	return s.New(a.Anonymous).Search(ctx, a.Query, a.Page, a.Limit)
}

func (s *Server) cacheStatus() (any, error) {
	st := s.Cache.Stat()
	return map[string]any{
		"dir":       st.Dir,
		"entries":   st.Entries,
		"bytes":     st.Bytes,
		"oldest":    st.Oldest,
		"newest":    st.Newest,
		"ttl_hours": s.Cfg.CacheTTL.Hours(),
		"has_key":   s.Cfg.HasKey(),
		"note": "The TTL is applied at read time, so lowering it in the config expires " +
			"entries already on disk. Keyed and anonymous answers are cached separately.",
	}, nil
}

func decodeArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return argErrorf("%v", err)
	}
	return nil
}

type argError struct{ msg string }

func (e *argError) Error() string { return e.msg }

func argErrorf(format string, args ...any) error {
	return &argError{msg: fmt.Sprintf(format, args...)}
}

// structuredError maps an error onto the {code, message} pair an agent sees.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": CodeInvalidArgument, "message": ae.msg}
	}
	if code := otx.Code(err); code != "" {
		return map[string]string{"code": code, "message": err.Error()}
	}
	return map[string]string{"code": CodeInvalidArgument, "message": err.Error()}
}
