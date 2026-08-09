package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
	"github.com/nlink-jp/otx-lookup/internal/workspace"
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
	`target under investigation. An indicator with no pulses is a normal result, not an error.`

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolLookupIndicator,
			"description": "Campaign context for one indicator (IPv4, IPv6, domain, hostname, URL, " +
				"MD5/SHA1/SHA256 hash, or CVE): the pulses that name it, plus aggregated adversaries, " +
				"malware families, ATT&CK techniques, targeted industries and countries. Finding no " +
				"pulses is a valid answer.",
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
					"workspace_root": map[string]any{"type": "string", "description": "Directory for file-mediated results when the pulse list is large."},
				},
				"required": []string{"indicator"},
			},
		},
		{
			"name": ToolGetPulse,
			"description": "One pulse in full, optionally with the indicators it carries — the pivot " +
				"from a single indicator to the rest of a campaign. Works without an API key; a key " +
				"additionally yields the exact indicator total.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pulse_id":       map[string]any{"type": "string", "description": "The pulse id, as returned by lookup_indicator."},
					"indicators":     map[string]any{"type": "boolean", "description": "Include the indicators the pulse carries."},
					"limit":          map[string]any{"type": "integer", "description": "Maximum indicators to return."},
					"anonymous":      map[string]any{"type": "boolean", "description": "Query without the configured API key."},
					"refresh":        map[string]any{"type": "boolean", "description": "Bypass the result cache."},
					"workspace_root": map[string]any{"type": "string", "description": "Directory for file-mediated results when the indicator list is large."},
				},
				"required": []string{"pulse_id"},
			},
		},
		{
			"name":        ToolSearchPulses,
			"description": "Search pulses by free text. Requires an OTX API key; without one this returns an auth_required error and spends no request.",
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
	WorkspaceRoot string   `json:"workspace_root"`
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

	// A heavily-reported indicator carries dozens of pulses. Spilling them to a
	// file keeps an agent's context for the analysis rather than the listing.
	if len(res.Pulses) > s.inlineMax() {
		path, werr := s.spill(a.WorkspaceRoot, "pulses-"+safeSlug(a.Indicator)+".jsonl", asRaw(res.Pulses))
		if werr == nil {
			trimmed := *res
			trimmed.Pulses = res.Pulses[:s.inlineMax()]
			return map[string]any{
				"result":         trimmed,
				"pulses_file":    path,
				"pulses_in_file": len(res.Pulses),
				"note": fmt.Sprintf("%d pulses were written to the file; the first %d are inline.",
					len(res.Pulses), s.inlineMax()),
			}, nil
		}
	}
	return res, nil
}

type pulseArgs struct {
	PulseID       string `json:"pulse_id"`
	Indicators    bool   `json:"indicators"`
	Limit         int    `json:"limit"`
	Anonymous     bool   `json:"anonymous"`
	Refresh       bool   `json:"refresh"`
	WorkspaceRoot string `json:"workspace_root"`
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
		Refresh:    a.Refresh,
	})
	if err != nil {
		return nil, err
	}

	if len(res.Indicators) > s.inlineMax() {
		path, werr := s.spill(a.WorkspaceRoot, "indicators-"+safeSlug(a.PulseID)+".jsonl", asRaw(res.Indicators))
		if werr == nil {
			trimmed := *res
			trimmed.Indicators = res.Indicators[:s.inlineMax()]
			return map[string]any{
				"result":             trimmed,
				"indicators_file":    path,
				"indicators_in_file": len(res.Indicators),
				"note": fmt.Sprintf("%d indicators were written to the file; the first %d are inline.",
					len(res.Indicators), s.inlineMax()),
			}, nil
		}
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

func (s *Server) inlineMax() int {
	if s.Cfg != nil && s.Cfg.MCPInlineMax > 0 {
		return s.Cfg.MCPInlineMax
	}
	return 200
}

// spill writes records to the caller's workspace, falling back to the
// configured one. It returns an error when neither is set, in which case the
// caller keeps the result inline rather than losing it.
func (s *Server) spill(root, name string, records []json.RawMessage) (string, error) {
	if strings.TrimSpace(root) == "" && s.Cfg != nil {
		root = s.Cfg.WorkspaceDir
	}
	if strings.TrimSpace(root) == "" {
		return "", fmt.Errorf("no workspace_root given and none configured")
	}
	ws, err := workspace.Open(root)
	if err != nil {
		return "", err
	}
	defer func() { _ = ws.Close() }()
	return ws.WriteJSONL(name, records)
}

func asRaw[T any](items []T) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// safeSlug reduces an indicator or id to something usable in a filename. The
// value can be a URL or a malware family id carrying slashes and brackets, so
// nothing is trusted through.
func safeSlug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 60 {
			break
		}
	}
	if b.Len() == 0 {
		return "result"
	}
	return strings.Trim(b.String(), ".")
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
