package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// stubEngine records what it was asked and returns canned answers.
type stubEngine struct {
	anonymous bool
	lookup    *engine.Result
	pulse     *engine.PulseResult
	search    *engine.SearchResult
	err       error

	lastTarget string
	lastOpts   engine.Options
	lastPulse  engine.PulseOptions
	lastQuery  string
}

func (s *stubEngine) Lookup(_ context.Context, target string, opts engine.Options) (*engine.Result, error) {
	s.lastTarget, s.lastOpts = target, opts
	return s.lookup, s.err
}

func (s *stubEngine) Pulse(_ context.Context, id string, opts engine.PulseOptions) (*engine.PulseResult, error) {
	s.lastPulse = opts
	return s.pulse, s.err
}

func (s *stubEngine) Search(_ context.Context, query string, page, limit int) (*engine.SearchResult, error) {
	s.lastQuery = query
	return s.search, s.err
}

func newServer(t *testing.T, stub *stubEngine) (*Server, *stubEngine) {
	t.Helper()
	cfg := &config.Config{
		BaseURL:      config.DefaultBaseURL,
		DefaultLimit: 10,
		CacheTTL:     24 * time.Hour,
		CacheDir:     t.TempDir(),
		MCPInlineMax: 2,
	}
	return &Server{
		Cfg:     cfg,
		Cache:   &cache.Store{Dir: cfg.CacheDir},
		Version: "test",
		New: func(anonymous bool) Engine {
			stub.anonymous = anonymous
			return stub
		},
	}, stub
}

// converse feeds newline-delimited requests and returns the decoded responses.
func converse(t *testing.T, s *Server, requests ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var responses []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("response is not JSON: %v\n%s", err, line)
		}
		responses = append(responses, m)
	}
	return responses
}

// toolPayload pulls the text content out of a tools/call response and decodes
// it, reporting whether the call was flagged as an error.
func toolPayload(t *testing.T, resp map[string]any) (map[string]any, bool) {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("response has no result: %v", resp)
	}
	isErr, _ := result["isError"].(bool)
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("result has no content: %v", result)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return map[string]any{"__text": text}, isErr
	}
	return payload, isErr
}

func TestInitializeAndToolsList(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	// The notification must not be answered.
	if len(responses) != 2 {
		t.Fatalf("got %d responses, want 2 (a notification must not be answered)", len(responses))
	}

	init := responses[0]["result"].(map[string]any)
	if init["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if info := init["serverInfo"].(map[string]any); info["name"] != "otx-lookup" || info["version"] != "test" {
		t.Errorf("serverInfo = %v", info)
	}
	if instr, _ := init["instructions"].(string); !strings.Contains(instr, "get_usage") {
		t.Error("instructions do not tell the agent to call get_usage first")
	}

	tools := responses[1]["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		m := tl.(map[string]any)
		names[m["name"].(string)] = true
		if _, ok := m["inputSchema"]; !ok {
			t.Errorf("tool %v has no inputSchema", m["name"])
		}
		if d, _ := m["description"].(string); d == "" {
			t.Errorf("tool %v has no description", m["name"])
		}
	}
	for _, want := range []string{ToolLookupIndicator, ToolGetPulse, ToolSearchPulses, ToolCacheStatus, ToolGetUsage} {
		if !names[want] {
			t.Errorf("tools/list is missing %s", want)
		}
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_usage","arguments":{}}}`)
	payload, isErr := toolPayload(t, responses[0])
	if isErr {
		t.Fatal("get_usage reported an error")
	}
	text, _ := payload["__text"].(string)
	if !strings.Contains(text, "otx-lookup MCP server") {
		t.Errorf("get_usage did not return the manual: %.120s", text)
	}
}

func TestLookupIndicatorPassesArgumentsThrough(t *testing.T) {
	s, stub := newServer(t, &stubEngine{lookup: &engine.Result{
		Query: "evil.test", Type: "domain", PulsesHeld: 1, PulsesShown: 1,
	}})

	// One frame per line: the transport is newline-delimited, so a request
	// split across lines would arrive as several malformed frames.
	responses := converse(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"indicator":"evil.test","sections":["reputation"],"limit":3,"anonymous":true,"refresh":true}}}`)

	payload, isErr := toolPayload(t, responses[0])
	if isErr {
		t.Fatalf("call failed: %v", payload)
	}
	if stub.lastTarget != "evil.test" {
		t.Errorf("target = %q", stub.lastTarget)
	}
	if len(stub.lastOpts.Sections) != 1 || stub.lastOpts.Sections[0] != "reputation" {
		t.Errorf("sections = %v", stub.lastOpts.Sections)
	}
	if stub.lastOpts.Limit != 3 || !stub.lastOpts.Refresh {
		t.Errorf("opts = %+v", stub.lastOpts)
	}
	if !stub.anonymous {
		t.Error("anonymous:true did not reach the engine factory")
	}
	if payload["query"] != "evil.test" {
		t.Errorf("payload = %v", payload)
	}
}

// The fields that decide whether an empty answer means anything must survive
// into the tool result, or an agent will read a failed lookup as a clean one.
func TestLookupResultKeepsTheHonestyFields(t *testing.T) {
	s, _ := newServer(t, &stubEngine{lookup: &engine.Result{
		Query: "paypal.com", Type: "hostname", PulsesHeld: 0, PulsesShown: 0,
		Incomplete: true, Degraded: []string{"type domain: 429"},
		TriedTypes: []string{"domain", "hostname"},
	}})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"indicator":"paypal.com"}}}`)
	payload, _ := toolPayload(t, responses[0])

	if payload["incomplete"] != true {
		t.Error("incomplete was lost; an agent would read this as a clean indicator")
	}
	if _, ok := payload["degraded"]; !ok {
		t.Error("degraded was lost")
	}
	if _, ok := payload["pulses_held"]; !ok {
		t.Error("pulses_held was lost")
	}
	if _, ok := payload["tried_types"]; !ok {
		t.Error("tried_types was lost")
	}
}

func TestMissingRequiredArgumentIsAnInvalidArgumentError(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	for _, call := range []string{
		`{"name":"lookup_indicator","arguments":{}}`,
		`{"name":"get_pulse","arguments":{}}`,
		`{"name":"search_pulses","arguments":{}}`,
	} {
		responses := converse(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+call+`}`)
		payload, isErr := toolPayload(t, responses[0])
		if !isErr {
			t.Errorf("%s: not flagged as an error", call)
		}
		if payload["code"] != CodeInvalidArgument {
			t.Errorf("%s: code = %v, want %s", call, payload["code"], CodeInvalidArgument)
		}
	}
}

// A misspelled argument is a mistake worth reporting, not one to ignore
// silently — an agent that passes `indicators: true` to lookup_indicator should
// learn that it did nothing.
func TestUnknownArgumentIsRejected(t *testing.T) {
	s, _ := newServer(t, &stubEngine{lookup: &engine.Result{}})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"indicator":"a.test","indicatorz":true}}}`)
	payload, isErr := toolPayload(t, responses[0])
	if !isErr || payload["code"] != CodeInvalidArgument {
		t.Errorf("an unknown argument was accepted: %v", payload)
	}
}

// Upstream failures keep their code, so an agent can branch on them.
func TestUpstreamErrorCodesSurvive(t *testing.T) {
	for _, tc := range []struct{ err, want string }{
		{otx.CodeAuthRequired, otx.CodeAuthRequired},
		{otx.CodeRateLimited, otx.CodeRateLimited},
		{otx.CodeNotFound, otx.CodeNotFound},
	} {
		s, _ := newServer(t, &stubEngine{err: &otx.Error{Code: tc.err, Message: "upstream says no"}})
		responses := converse(t, s,
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"indicator":"a.test"}}}`)
		payload, isErr := toolPayload(t, responses[0])
		if !isErr {
			t.Errorf("%s: not flagged as an error", tc.err)
		}
		if payload["code"] != tc.want {
			t.Errorf("code = %v, want %v", payload["code"], tc.want)
		}
	}
}

// A tool failure is a result, not a JSON-RPC error: a protocol error would be
// swallowed by the client instead of reaching the model.
func TestToolFailureIsAResultNotAProtocolError(t *testing.T) {
	s, _ := newServer(t, &stubEngine{err: &otx.Error{Code: otx.CodeNotFound, Message: "gone"}})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_indicator","arguments":{"indicator":"a.test"}}}`)
	if _, ok := responses[0]["error"]; ok {
		t.Error("a tool failure was returned as a JSON-RPC error")
	}
}

func TestUnknownToolAndMethod(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"nosuch/method"}`)

	payload, isErr := toolPayload(t, responses[0])
	if !isErr || !strings.Contains(payload["message"].(string), "nope") {
		t.Errorf("unknown tool: %v", payload)
	}
	if _, ok := responses[1]["error"]; !ok {
		t.Error("an unknown method should be a JSON-RPC error")
	}
}

// A malformed frame must be answered, or the client waits forever.
func TestMalformedFrameGetsAParseError(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s, `{not json`, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(responses) != 2 {
		t.Fatalf("got %d responses, want 2", len(responses))
	}
	errObj, ok := responses[0]["error"].(map[string]any)
	if !ok || errObj["code"].(float64) != -32700 {
		t.Errorf("malformed frame response = %v", responses[0])
	}
	// And the session must continue.
	if _, ok := responses[1]["result"]; !ok {
		t.Error("the session did not continue after a malformed frame")
	}
}

// Large lists go to a file so an agent's context is spent on analysis rather
// than on a listing.
func TestLargeIndicatorListSpillsToTheWorkspace(t *testing.T) {
	inds := make([]otx.PulseIndicator, 5)
	for i := range inds {
		inds[i] = otx.PulseIndicator{ID: int64(i), Indicator: "x.test", Type: "domain", IsActive: 1}
	}
	s, _ := newServer(t, &stubEngine{pulse: &engine.PulseResult{
		ID: "p1", Name: "Big", Indicators: inds, IndicatorsShown: 5, IndicatorsHeld: -1,
	}})
	ws := t.TempDir()

	responses := converse(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pulse","arguments":{"pulse_id":"p1","indicators":true,"workspace_root":"`+ws+`"}}}`)
	payload, isErr := toolPayload(t, responses[0])
	if isErr {
		t.Fatalf("call failed: %v", payload)
	}
	path, _ := payload["indicators_file"].(string)
	if path == "" {
		t.Fatalf("no indicators_file in the result: %v", payload)
	}
	if payload["indicators_in_file"].(float64) != 5 {
		t.Errorf("indicators_in_file = %v, want 5", payload["indicators_in_file"])
	}
	if !strings.HasPrefix(path, ws) {
		t.Errorf("file %q was written outside the workspace %q", path, ws)
	}
	// The inline part is capped, but present, so the agent sees a sample.
	inner := payload["result"].(map[string]any)
	if n := len(inner["indicators"].([]any)); n != s.inlineMax() {
		t.Errorf("inline indicators = %d, want %d", n, s.inlineMax())
	}
}

// With no workspace anywhere the result must still come back, just inline.
func TestNoWorkspaceKeepsResultsInline(t *testing.T) {
	inds := make([]otx.PulseIndicator, 5)
	s, _ := newServer(t, &stubEngine{pulse: &engine.PulseResult{ID: "p1", Indicators: inds}})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_pulse","arguments":{"pulse_id":"p1","indicators":true}}}`)
	payload, isErr := toolPayload(t, responses[0])
	if isErr {
		t.Fatalf("call failed: %v", payload)
	}
	if _, ok := payload["indicators_file"]; ok {
		t.Error("a file was reported without a workspace")
	}
	if len(payload["indicators"].([]any)) != 5 {
		t.Errorf("the result was truncated with nowhere to put the rest: %v", payload["indicators"])
	}
}

func TestCacheStatusReportsTheConfiguration(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cache_status","arguments":{}}}`)
	payload, isErr := toolPayload(t, responses[0])
	if isErr {
		t.Fatalf("call failed: %v", payload)
	}
	for _, k := range []string{"dir", "entries", "ttl_hours", "has_key"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("cache_status is missing %q: %v", k, payload)
		}
	}
}

func TestServeRefusesANilInput(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	var out bytes.Buffer
	if err := s.Serve(context.Background(), nil, &out); err == nil {
		t.Error("a nil input stream was accepted")
	}
}
