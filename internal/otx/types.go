package otx

import (
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

// AttackID is a MITRE ATT&CK technique. Measured shape:
// {id, name, display_name} — e.g. T1041 / "Exfiltration Over C2 Channel".
type AttackID struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
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
