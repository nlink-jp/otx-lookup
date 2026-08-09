package indicator

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Type is an OTX indicator type, spelled the way it appears in an API path.
type Type string

const (
	TypeIPv4     Type = "IPv4"
	TypeIPv6     Type = "IPv6"
	TypeDomain   Type = "domain"
	TypeHostname Type = "hostname"
	TypeURL      Type = "url"
	TypeFile     Type = "file"
	TypeCVE      Type = "cve"
)

// Indicator is a classified, normalized target.
type Indicator struct {
	Raw      string // exactly what the user typed
	Type     Type   // the type to query first
	Value    string // normalized value, as OTX echoes it back
	Alt      Type   // second type to try, or "" when the type is unambiguous
	HashKind string // "md5" / "sha1" / "sha256" when Type is TypeFile
}

// Types returns the types to try, in order.
func (i Indicator) Types() []Type {
	if i.Alt == "" {
		return []Type{i.Type}
	}
	return []Type{i.Type, i.Alt}
}

// PathFor returns the "<type>/<value>" path segment pair for one type.
func (i Indicator) PathFor(t Type) string {
	return string(t) + "/" + url.PathEscape(i.Value)
}

// Classify determines an indicator's type from its shape and normalizes it.
//
// This is a gate, not a convenience: it runs before any network I/O, so a
// malformed target never reaches OTX. Order matters — the checks run from the
// most distinctive shape to the least, so a 64-character hex string is never
// mistaken for a hostname.
func Classify(s string) (Indicator, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Indicator{}, fmt.Errorf("empty indicator")
	}
	if i := strings.IndexFunc(raw, isControl); i >= 0 {
		return Indicator{}, fmt.Errorf("indicator contains a control character at byte %d", i)
	}

	if v, ok := classifyCVE(raw); ok {
		return Indicator{Raw: raw, Type: TypeCVE, Value: v}, nil
	}
	if v, err, ok := classifyURL(raw); ok {
		if err != nil {
			return Indicator{}, err
		}
		return Indicator{Raw: raw, Type: TypeURL, Value: v}, nil
	}
	if v, kind, ok := classifyHash(raw); ok {
		return Indicator{Raw: raw, Type: TypeFile, Value: v, HashKind: kind}, nil
	}
	if addr, err := netip.ParseAddr(raw); err == nil {
		t := TypeIPv4
		if addr.Is6() && !addr.Is4In6() {
			t = TypeIPv6
		}
		return Indicator{Raw: raw, Type: t, Value: addr.Unmap().String()}, nil
	}
	return classifyName(raw)
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// classifyCVE recognizes CVE-YYYY-NNNN(+). OTX uppercases the identifier.
func classifyCVE(s string) (string, bool) {
	up := strings.ToUpper(s)
	rest, ok := strings.CutPrefix(up, "CVE-")
	if !ok {
		return "", false
	}
	year, num, ok := strings.Cut(rest, "-")
	if !ok || len(year) != 4 || !allDigits(year) || len(num) < 4 || !allDigits(num) {
		return "", false
	}
	return up, true
}

// classifyURL recognizes anything carrying a scheme separator. Requiring the
// scheme is what keeps "example.com/path" from being ambiguous with a hostname:
// a target meant as a URL is spelled as one.
//
// The third return value reports whether the input looked like a URL at all, so
// a malformed URL is an error rather than falling through to be misread as a
// hostname.
func classifyURL(s string) (string, error, bool) {
	if !strings.Contains(s, "://") {
		return "", nil, false
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", s, err), true
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q: only http and https URLs are indicators (got scheme %q)", s, u.Scheme), true
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q is not a valid URL: no host", s), true
	}
	return s, nil, true
}

// classifyHash recognizes a bare hex digest by length: 32 (MD5), 40 (SHA1),
// 64 (SHA256). OTX matches hashes in lowercase.
func classifyHash(s string) (value, kind string, ok bool) {
	kinds := map[int]string{32: "md5", 40: "sha1", 64: "sha256"}
	k, sized := kinds[len(s)]
	if !sized || !allHex(s) {
		return "", "", false
	}
	return strings.ToLower(s), k, true
}

// classifyName handles DNS names, and picks between OTX's two name types.
//
// The choice is load-bearing and the failure is silent. OTX indexes a name's
// pulses under exactly one of `domain` or `hostname`, but both endpoints answer
// 200 with a well-formed body either way — the wrong one simply reports zero
// pulses. Measured 2026-08-09:
//
//	domain/paypal.com        50 pulses     hostname/paypal.com         0
//	hostname/www.bbc.co.uk   50 pulses     domain/www.bbc.co.uk        0
//	domain/bbc.co.uk         22 pulses     hostname/bbc.co.uk          0
//
// The distinction is registrable-domain versus name-with-a-subdomain, which is
// a public-suffix question: bbc.co.uk has three labels and is a domain, while
// mail.google.com has three labels and is a hostname. Counting labels cannot
// settle it and a bundled suffix list would rot.
//
// So the label count only orders the attempts, and the caller tries the
// alternate when the first returns nothing. That costs one extra request in the
// no-pulses case — cheap against a 10,000/h budget — and removes a false
// negative that would otherwise be indistinguishable from a clean indicator.
func classifyName(s string) (Indicator, error) {
	name := strings.ToLower(strings.TrimSuffix(s, "."))
	if err := validateName(name); err != nil {
		return Indicator{}, err
	}
	if strings.Count(name, ".") == 1 {
		return Indicator{Raw: s, Type: TypeDomain, Value: name, Alt: TypeHostname}, nil
	}
	return Indicator{Raw: s, Type: TypeHostname, Value: name, Alt: TypeDomain}, nil
}

func validateName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("%q is too long for a DNS name (%d bytes, max 253)", name, len(name))
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q is not a lookup target: expected an IP, a domain, a URL, a file hash, or a CVE identifier", name)
	}
	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%q has an empty label", name)
		}
		if len(l) > 63 {
			return fmt.Errorf("%q has a label longer than 63 bytes", name)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with a hyphen", name)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			case c >= 0x80:
				return fmt.Errorf("%q is not ASCII: pass the punycode (xn--) form", name)
			default:
				return fmt.Errorf("%q contains %q, which is not valid in a DNS name", name, string(c))
			}
		}
	}
	// A name whose last label is numeric is a malformed address, not a domain;
	// netip already rejected it, and OTX answers 400.
	if allDigits(labels[len(labels)-1]) {
		return fmt.Errorf("%q is not a valid IP address or DNS name", name)
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return s != ""
}

// sectionsByType lists what OTX offers per indicator type, measured against the
// live API on 2026-08-09. A `general` response also carries its own `sections`
// array, so this table is for validating a --sections request before spending a
// round trip, not for deciding what exists.
var sectionsByType = map[Type][]string{
	TypeIPv4:     {"general", "geo", "reputation", "url_list", "passive_dns", "malware", "nids_list", "http_scans"},
	TypeIPv6:     {"general", "geo", "reputation", "url_list", "passive_dns", "malware", "nids_list", "http_scans"},
	TypeDomain:   {"general", "geo", "url_list", "passive_dns", "malware", "whois", "http_scans"},
	TypeHostname: {"general", "geo", "url_list", "passive_dns", "malware", "whois", "http_scans"},
	TypeFile:     {"general", "analysis"},
	TypeURL:      {"general", "url_list", "http_scans", "screenshot"},
	TypeCVE:      {"general", "nids_list", "malware"},
}

// Sections returns the sections OTX offers for a type.
func Sections(t Type) []string { return sectionsByType[t] }

// HasSection reports whether OTX offers a section for a type.
func HasSection(t Type, section string) bool {
	for _, s := range sectionsByType[t] {
		if s == section {
			return true
		}
	}
	return false
}

// overlapOwner names the sibling tool that owns a section. These are the
// sections kept out of the default set: each is answered better elsewhere, and
// emitting both would leave the analyst with two answers and no basis to choose.
var overlapOwner = map[string]string{
	"reputation":  "abuse-lookup",
	"passive_dns": "rdns-lookup",
	"malware":     "malware-lookup",
	"analysis":    "malware-lookup",
	"url_list":    "urlscan-lookup",
}

// OverlapOwner returns the sibling tool that owns a section, or "" when no
// sibling covers it.
func OverlapOwner(section string) string { return overlapOwner[section] }

// DefaultSections is what a lookup fetches when --sections is not given.
//
// Just `general`, because `general` is where pulse_info lives — the campaign
// context that is this tool's whole reason to exist. One request per indicator,
// and nothing that duplicates a sibling tool.
func DefaultSections() []string { return []string{"general"} }
