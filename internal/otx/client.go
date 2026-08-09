package otx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Error codes. They are the contract the MCP layer surfaces as
// {code, message}, so an agent can branch on them without parsing prose.
const (
	CodeBadRequest   = "bad_request"    // upstream rejected the indicator itself
	CodeAuthRequired = "auth_required"  // endpoint needs an API key
	CodeNotFound     = "not_found"      // no such object
	CodeRateLimited  = "rate_limited"   // budget exhausted
	CodeUpstream     = "upstream_error" // 5xx or an unexpected status
	CodeNetwork      = "network_error"  // the request never completed
	CodeDecode       = "decode_error"   // the body was not the JSON we expect
)

// Error is a structured upstream failure.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

// Code returns the error's code, or "" when err is not an *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// maxBody caps how much of a response is read. A pulse indicator page is large
// but bounded; anything past this is a malfunction, not data.
const maxBody = 32 << 20

// Doer is the HTTP surface the client depends on, so tests inject a stub.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client talks to the OTX DirectConnect API.
type Client struct {
	BaseURL   string
	APIKey    string
	UserAgent string
	HTTP      Doer

	// Now and Sleep are injected so rate pacing is deterministic in tests.
	Now   func() time.Time
	Sleep func(time.Duration)

	limiter *limiter
}

// New builds a client. maxPerHour is the request budget to stay under; OTX
// returns no remaining-budget header, so the count is kept locally.
func New(baseURL, apiKey string, timeout time.Duration, maxPerHour int, userAgent string) *Client {
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		UserAgent: userAgent,
		HTTP:      &http.Client{Timeout: timeout},
		Now:       time.Now,
		Sleep:     time.Sleep,
		limiter:   &limiter{max: maxPerHour, window: time.Hour},
	}
}

// HasKey reports whether the client is authenticated.
func (c *Client) HasKey() bool { return c.APIKey != "" }

// Requests returns how many requests the client has made inside the current
// rate window. Reported as provenance so a partial bulk run is explainable.
func (c *Client) Requests() int {
	if c.limiter == nil {
		return 0
	}
	return len(c.limiter.times)
}

// IndicatorSection fetches one section of one indicator, e.g.
// GET /indicators/domain/example.com/general.
//
// Every section answers anonymously for every indicator type.
func (c *Client) IndicatorSection(ctx context.Context, typ, value, section string) (json.RawMessage, error) {
	path := "/indicators/" + typ + "/" + url.PathEscape(value) + "/" + url.PathEscape(section)
	return c.get(ctx, path, nil)
}

// General fetches and decodes an indicator's general section — the one that
// carries pulse_info.
func (c *Client) General(ctx context.Context, typ, value string) (*General, error) {
	raw, err := c.IndicatorSection(ctx, typ, value, "general")
	if err != nil {
		return nil, err
	}
	var g General
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("decode general for %s/%s: %v", typ, value, err)}
	}
	g.Raw = raw
	return &g, nil
}

// Pulse fetches a pulse's detail. Answers anonymously.
func (c *Client) Pulse(ctx context.Context, id string) (json.RawMessage, error) {
	return c.get(ctx, "/pulses/"+url.PathEscape(id), nil)
}

// Account fetches the account the API key belongs to.
//
// This is the only way to tell a valid key from a typo. Every other endpoint
// either ignores the key (the indicator sections answer anonymously, so a bad
// key still returns 200) or needs one for reasons of its own — so a lookup
// succeeding proves nothing about the key.
func (c *Client) Account(ctx context.Context) (*Account, error) {
	if !c.HasKey() {
		return nil, errNeedsKey("checking the API key")
	}
	raw, err := c.get(ctx, "/users/me", nil)
	if err != nil {
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("decode account: %v", err)}
	}
	a.Raw = raw
	return &a, nil
}

// PulseDetail fetches and decodes a pulse. Answers anonymously, and the
// response embeds an `indicators` array — which is what makes pivoting from a
// pulse to its other indicators possible without a key.
func (c *Client) PulseDetail(ctx context.Context, id string) (*PulseDetail, error) {
	raw, err := c.Pulse(ctx, id)
	if err != nil {
		return nil, err
	}
	var p PulseDetail
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("decode pulse %s: %v", id, err)}
	}
	p.Raw = raw
	return &p, nil
}

// PulseRelated fetches the pulses related to a pulse. Answers anonymously.
func (c *Client) PulseRelated(ctx context.Context, id string) (json.RawMessage, error) {
	return c.get(ctx, "/pulses/"+url.PathEscape(id)+"/related", nil)
}

// PulseIndicatorPage fetches one page of a pulse's indicators, decoded.
func (c *Client) PulseIndicatorPage(ctx context.Context, id string, page, limit int) (*IndicatorPage, error) {
	raw, err := c.PulseIndicators(ctx, id, page, limit)
	if err != nil {
		return nil, err
	}
	var p IndicatorPage
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("decode indicators of pulse %s: %v", id, err)}
	}
	p.Raw = raw
	return &p, nil
}

// Search runs a pulse search, decoded.
func (c *Client) Search(ctx context.Context, query string, page, limit int) (*SearchResults, error) {
	raw, err := c.SearchPulses(ctx, query, page, limit)
	if err != nil {
		return nil, err
	}
	var s SearchResults
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("decode search results for %q: %v", query, err)}
	}
	s.Raw = raw
	return &s, nil
}

// PulseIndicators fetches the indicators inside a pulse.
//
// This is one of the three endpoints that require a key — measured: 403 without
// one, while the pulse's own detail answers anonymously. The check happens
// before the request so the failure is precise and costs no quota.
func (c *Client) PulseIndicators(ctx context.Context, id string, page, limit int) (json.RawMessage, error) {
	if !c.HasKey() {
		return nil, errNeedsKey("the indicator list inside a pulse")
	}
	q := url.Values{}
	setPaging(q, page, limit)
	return c.get(ctx, "/pulses/"+url.PathEscape(id)+"/indicators", q)
}

// SearchSort is the ordering asked for in a pulse search.
//
// Upstream's own default is oldest-first: searching "qakbot" leads with reports
// from 2015, which is the least useful answer a triage could get. Newest-first
// is requested explicitly.
const SearchSort = "-modified"

// SearchPulses searches pulses. Requires a key (measured: 403 without one).
func (c *Client) SearchPulses(ctx context.Context, query string, page, limit int) (json.RawMessage, error) {
	if !c.HasKey() {
		return nil, errNeedsKey("pulse search")
	}
	q := url.Values{"q": {query}, "sort": {SearchSort}}
	setPaging(q, page, limit)
	return c.get(ctx, "/search/pulses", q)
}

func errNeedsKey(what string) error {
	return &Error{
		Code:   CodeAuthRequired,
		Status: http.StatusForbidden,
		Message: what + " requires an OTX API key; set OTX_LOOKUP_API_KEY or [api] key " +
			"(indicator lookups and pulse details work without one)",
	}
}

func setPaging(q url.Values, page, limit int) {
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
}

func (c *Client) get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	endpoint := c.BaseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: fmt.Sprintf("build request for %s: %v", path, err)}
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.APIKey != "" {
		// The key travels in this header and nowhere else — never in the query
		// string, where it would reach proxy logs and shell history.
		req.Header.Set("X-OTX-API-KEY", c.APIKey)
	}

	c.pace()

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: fmt.Sprintf("request %s: %v", path, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: fmt.Sprintf("read %s: %v", path, err), Status: resp.StatusCode}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, path, body)
	}
	if !json.Valid(body) {
		return nil, &Error{Code: CodeDecode, Message: fmt.Sprintf("%s returned a body that is not JSON", path), Status: resp.StatusCode}
	}
	return json.RawMessage(body), nil
}

// statusError maps upstream statuses onto the error codes, using what the live
// API actually returns: 400 for a malformed indicator, 403 for the three
// key-only endpoints, 404 for an unknown hash or pulse.
func statusError(status int, path string, body []byte) *Error {
	detail := upstreamDetail(body)
	switch status {
	case http.StatusBadRequest:
		return &Error{Code: CodeBadRequest, Status: status,
			Message: fmt.Sprintf("upstream rejected %s as malformed%s", path, detail)}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &Error{Code: CodeAuthRequired, Status: status,
			Message: fmt.Sprintf("%s requires a valid OTX API key%s", path, detail)}
	case http.StatusNotFound:
		return &Error{Code: CodeNotFound, Status: status,
			Message: fmt.Sprintf("%s is not known to OTX%s", path, detail)}
	case http.StatusTooManyRequests:
		return &Error{Code: CodeRateLimited, Status: status,
			Message: fmt.Sprintf("OTX rate limit reached on %s%s", path, detail)}
	default:
		return &Error{Code: CodeUpstream, Status: status,
			Message: fmt.Sprintf("%s returned HTTP %d%s", path, status, detail)}
	}
}

// upstreamDetail extracts an error message from the body when there is one,
// so the operator sees upstream's own words rather than only a status code.
func upstreamDetail(body []byte) string {
	var payload struct {
		Detail string `json:"detail"`
		Error  string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if msg := strings.TrimSpace(firstNonEmpty(payload.Detail, payload.Error)); msg != "" {
			return ": " + msg
		}
	}
	s := strings.TrimSpace(string(body))
	// A gateway error arrives as an HTML page (a 504 from OTX is a full
	// <html> document). Pasting markup into an operator's terminal explains
	// nothing the status code did not already say.
	if s == "" || strings.HasPrefix(s, "<") || len(s) > 200 {
		return ""
	}
	return ": " + s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (c *Client) pace() {
	if c.limiter == nil {
		return
	}
	now, sleep := c.Now, c.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	c.limiter.take(now, sleep)
}

// limiter is a sliding-window request counter.
//
// It exists because OTX sends no rate-budget header — unlike ip.thc.org, there
// is nothing to read and pace against, so the only way to stay inside the
// published ceiling is to count locally.
type limiter struct {
	max    int
	window time.Duration
	times  []time.Time
}

func (l *limiter) take(now func() time.Time, sleep func(time.Duration)) {
	if l.max <= 0 {
		return
	}
	t := now()
	l.prune(t)
	if len(l.times) >= l.max {
		// Wait until the oldest request leaves the window.
		wait := l.window - t.Sub(l.times[0])
		if wait > 0 {
			sleep(wait)
			t = now()
			l.prune(t)
		}
	}
	l.times = append(l.times, t)
}

func (l *limiter) prune(now time.Time) {
	cut := 0
	for cut < len(l.times) && now.Sub(l.times[cut]) >= l.window {
		cut++
	}
	l.times = l.times[cut:]
}
