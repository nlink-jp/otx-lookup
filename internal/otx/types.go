package otx

import (
	"bytes"
	"encoding/json"
	"time"
)

// TimeLayout is how OTX spells a timestamp: "2026-03-23T00:25:09.116000".
//
// Note what is missing — there is no zone designator and no offset. The values
// are UTC in practice, so ParseTime reads them as UTC rather than as local
// time, which would shift every timeline by the operator's offset.
const TimeLayout = "2006-01-02T15:04:05.999999"

// ParseTime parses an OTX timestamp as UTC. An unparseable value yields the
// zero time and false: a malformed date in one pulse must not fail a lookup.
func ParseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(TimeLayout, s)
	if err != nil {
		// Some fields do carry a zone; accept RFC 3339 as well.
		if t, err2 := time.Parse(time.RFC3339, s); err2 == nil {
			return t.UTC(), true
		}
		return time.Time{}, false
	}
	return t.UTC(), true
}

// General is the part of an indicator's `general` section this tool reads.
//
// Only the common fields are decoded. The rest of the response varies widely by
// indicator type — an IPv4 carries geo fields, a CVE carries cvss/epss/exploits
// /products — and decoding all of it would mean a struct that breaks whenever
// OTX adds a type. Raw keeps the whole body for --json.
type General struct {
	Indicator string   `json:"indicator"`
	Type      string   `json:"type"`
	TypeTitle string   `json:"type_title"`
	Sections  []string `json:"sections"`

	// Validation is upstream's own note that an indicator is unlikely to be
	// worth alerting on (a whitelisted domain, for example). Measured shape:
	// {message, name, source}.
	Validation []Validation `json:"validation"`

	// FalsePositive holds community false-positive reports. The populated
	// shape has never been observed, so it is kept raw rather than decoded
	// into invented field names: the count is reported, and --json passes the
	// array through verbatim.
	FalsePositive []json.RawMessage `json:"false_positive"`

	PulseInfo PulseInfo `json:"pulse_info"`

	// Raw is the entire response body, preserved for --json and --raw.
	Raw json.RawMessage `json:"-"`
}

// Validation is an upstream note that an indicator is probably not worth
// alerting on.
type Validation struct {
	Source  string `json:"source"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

// PulseInfo is the campaign context — the reason this tool exists.
type PulseInfo struct {
	// Count is how many pulses upstream reports. Treat it as a lower bound:
	// it comes back as exactly 50 for heavily-reported indicators, which is a
	// page size rather than a total. Never present it as the true number.
	Count      int             `json:"count"`
	Pulses     []Pulse         `json:"pulses"`
	References []string        `json:"references"`
	Related    json.RawMessage `json:"related"`
}

// Pulse is one community report.
type Pulse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Author      Author `json:"author"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	TLP         string `json:"TLP"`
	Public      int    `json:"public"`

	Adversary         string     `json:"adversary"`
	MalwareFamilies   []NamedRef `json:"malware_families"`
	AttackIDs         []AttackID `json:"attack_ids"`
	Industries        []string   `json:"industries"`
	TargetedCountries []string   `json:"targeted_countries"`
	Tags              []string   `json:"tags"`
	References        []string   `json:"references"`

	IndicatorCount      int            `json:"indicator_count"`
	IndicatorTypeCounts map[string]int `json:"indicator_type_counts"`

	SubscriberCount int `json:"subscriber_count"`
	UpvotesCount    int `json:"upvotes_count"`
	DownvotesCount  int `json:"downvotes_count"`
}

// CreatedAt and ModifiedAt parse the pulse timestamps, reporting whether the
// value was usable.
func (p Pulse) CreatedAt() (time.Time, bool)  { return ParseTime(p.Created) }
func (p Pulse) ModifiedAt() (time.Time, bool) { return ParseTime(p.Modified) }

// Author identifies who submitted a pulse. Who reported something is evidence
// about how much weight it deserves, so it is always shown.
type Author struct {
	Username string `json:"username"`
	ID       string `json:"id"`
}

// NamedRef is a malware family (or similar) reference. Measured shape:
// {id, display_name, target}. The id can contain backslashes and brackets —
// "Win32:MalOb-BX\\ [Cryp]" is a real value — so it is never used as a path
// segment or a filename without escaping.
type NamedRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Target      string `json:"target"`
}

// Label prefers the display name and falls back to the id.
func (n NamedRef) Label() string {
	if n.DisplayName != "" {
		return n.DisplayName
	}
	return n.ID
}

// UnmarshalJSON accepts either the object form or a bare string.
//
// The pulse summary inside pulse_info uses objects. The pulse detail's own
// malware_families has only ever been observed empty, so the bare-string form
// cannot be ruled out — and a shape difference between two representations of
// the same field would otherwise fail the whole decode.
func (n *NamedRef) UnmarshalJSON(b []byte) error {
	if s, ok, err := decodeBareString(b); ok {
		n.ID, n.DisplayName = s, s
		return err
	}
	type plain NamedRef
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*n = NamedRef(p)
	return nil
}

// AttackID is a MITRE ATT&CK technique. Measured shape:
// {id, name, display_name} — e.g. T1041 / "Exfiltration Over C2 Channel".
type AttackID struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// UnmarshalJSON accepts either the object form or a bare technique id, for the
// same reason as NamedRef.
func (a *AttackID) UnmarshalJSON(b []byte) error {
	if s, ok, err := decodeBareString(b); ok {
		a.ID = s
		return err
	}
	type plain AttackID
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*a = AttackID(p)
	return nil
}

func decodeBareString(b []byte) (string, bool, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", false, nil
	}
	var s string
	err := json.Unmarshal(trimmed, &s)
	return s, true, err
}

// PulseDetail is GET /pulses/{id}.
//
// It embeds an `indicators` array and answers anonymously, which is what makes
// pivoting from a pulse to its other indicators possible without an API key.
// The catch is that the response carries no total and no pagination cursor, so
// the embedded set cannot be assumed complete — see engine.PulseResult.
type PulseDetail struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Author      Author `json:"author"`
	AuthorName  string `json:"author_name"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	TLP         string `json:"TLP"`
	Public      int    `json:"public"`
	Revision    int    `json:"revision"`

	Adversary         string     `json:"adversary"`
	MalwareFamilies   []NamedRef `json:"malware_families"`
	AttackIDs         []AttackID `json:"attack_ids"`
	Industries        []string   `json:"industries"`
	TargetedCountries []string   `json:"targeted_countries"`
	Tags              []string   `json:"tags"`
	References        []string   `json:"references"`

	Indicators []PulseIndicator `json:"indicators"`

	Raw json.RawMessage `json:"-"`
}

// CreatedAt and ModifiedAt parse the detail timestamps.
func (p PulseDetail) CreatedAt() (time.Time, bool)  { return ParseTime(p.Created) }
func (p PulseDetail) ModifiedAt() (time.Time, bool) { return ParseTime(p.Modified) }

// PulseIndicator is one indicator carried by a pulse. Measured shape:
// {content, created, description, expiration, id, indicator, is_active, title,
// type}, where id is a number, is_active is 0/1, and expiration may be null.
// Note that `created` here has no fractional seconds ("2025-12-03T20:00:02"),
// unlike the pulse timestamps. The paginated endpoint adds `pulse_key`; the
// copy embedded in a pulse detail does not carry it.
type PulseIndicator struct {
	ID          int64   `json:"id"`
	Indicator   string  `json:"indicator"`
	Type        string  `json:"type"`
	Created     string  `json:"created"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Content     string  `json:"content"`
	IsActive    int     `json:"is_active"`
	Expiration  *string `json:"expiration"`
	PulseKey    string  `json:"pulse_key"`
}

// Active reports whether the indicator is still marked live by its pulse.
func (p PulseIndicator) Active() bool { return p.IsActive != 0 }

// IndicatorPage is GET /pulses/{id}/indicators — the paginated view, which
// requires an API key. Measured 2026-08-10: {count, next, previous, results},
// with `next` a full URL rather than a cursor.
//
// Its `count` is the only place upstream states how many indicators a pulse
// holds. Measured against the detail endpoint at 30, 202 and 4090 indicators,
// the two always agreed — the detail returns the complete set rather than a
// page. It cannot be relied on beyond that: a pulse with ~335,000 indicators
// made the detail time out entirely, so the failure mode at the top end is a
// dead request, not a silent truncation.
type IndicatorPage struct {
	Count    int              `json:"count"`
	Next     *string          `json:"next"`
	Previous *string          `json:"previous"`
	Results  []PulseIndicator `json:"results"`

	Raw json.RawMessage `json:"-"`
}

// SearchResults is GET /search/pulses, which also requires an API key.
// Measured 2026-08-10: {count, exact_match, next, previous, results}.
//
// The pulses in `results` are a reduced form: they carry the campaign metadata
// but no indicator_count, subscriber_count or vote counts, so those fields
// decode as zero. Do not present a zero from here as a real count.
//
// ExactMatch is deliberately left raw. It is documented as a boolean and
// arrives as a string (empty in every observed response), and declaring it
// `bool` made the whole search fail to decode — a defect that reached a live
// run. Nothing depends on it; keeping it raw means a further change of type
// cannot break search again.
type SearchResults struct {
	Count      int             `json:"count"`
	ExactMatch json.RawMessage `json:"exact_match"`
	Next       *string         `json:"next"`
	Previous   *string         `json:"previous"`
	Results    []Pulse         `json:"results"`

	Raw json.RawMessage `json:"-"`
}

// Label prefers the display name, then "id - name", then the id.
func (a AttackID) Label() string {
	switch {
	case a.DisplayName != "":
		return a.DisplayName
	case a.ID != "" && a.Name != "":
		return a.ID + " - " + a.Name
	default:
		return a.ID
	}
}
