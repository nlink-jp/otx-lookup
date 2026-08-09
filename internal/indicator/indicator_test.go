package indicator

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		in       string
		wantType Type
		wantVal  string
		wantAlt  Type
		wantKind string
	}{
		// CVE — case-insensitive in, uppercase out.
		{"CVE-2021-44228", TypeCVE, "CVE-2021-44228", "", ""},
		{"cve-2021-44228", TypeCVE, "CVE-2021-44228", "", ""},
		{"CVE-2026-123456", TypeCVE, "CVE-2026-123456", "", ""},

		// URL — the scheme is what makes it a URL rather than a hostname.
		{"http://example.com", TypeURL, "http://example.com", "", ""},
		{"https://example.com/a?b=1", TypeURL, "https://example.com/a?b=1", "", ""},

		// Hashes, by length. OTX matches lowercase.
		{"b234ee4d69f5fce4486a80fdaf4a4263", TypeFile, "b234ee4d69f5fce4486a80fdaf4a4263", "", "md5"},
		{"B234EE4D69F5FCE4486A80FDAF4A4263", TypeFile, "b234ee4d69f5fce4486a80fdaf4a4263", "", "md5"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", TypeFile, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "", "sha1"},
		{
			"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
			TypeFile, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "", "sha256",
		},

		// Addresses.
		{"8.8.8.8", TypeIPv4, "8.8.8.8", "", ""},
		{"2001:4860:4860::8888", TypeIPv6, "2001:4860:4860::8888", "", ""},
		{"::ffff:8.8.8.8", TypeIPv4, "8.8.8.8", "", ""}, // 4-in-6 is an IPv4 indicator

		// Names. Two labels lead with domain, more with hostname; the other is
		// always kept as the alternate, because label count cannot settle it.
		{"paypal.com", TypeDomain, "paypal.com", TypeHostname, ""},
		{"PayPal.COM", TypeDomain, "paypal.com", TypeHostname, ""},
		{"paypal.com.", TypeDomain, "paypal.com", TypeHostname, ""},
		{"www.example.com", TypeHostname, "www.example.com", TypeDomain, ""},
		{"bbc.co.uk", TypeHostname, "bbc.co.uk", TypeDomain, ""}, // really a domain; the fallback finds it
	}

	for _, tc := range tests {
		got, err := Classify(tc.in)
		if err != nil {
			t.Errorf("Classify(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got.Type != tc.wantType {
			t.Errorf("Classify(%q).Type = %q, want %q", tc.in, got.Type, tc.wantType)
		}
		if got.Value != tc.wantVal {
			t.Errorf("Classify(%q).Value = %q, want %q", tc.in, got.Value, tc.wantVal)
		}
		if got.Alt != tc.wantAlt {
			t.Errorf("Classify(%q).Alt = %q, want %q", tc.in, got.Alt, tc.wantAlt)
		}
		if got.HashKind != tc.wantKind {
			t.Errorf("Classify(%q).HashKind = %q, want %q", tc.in, got.HashKind, tc.wantKind)
		}
	}
}

func TestClassifyRejects(t *testing.T) {
	tests := []struct {
		in     string
		reason string
	}{
		{"", "empty"},
		{"   ", "empty after trimming"},
		{"evil.com\r\nHost: x", "CRLF injection into the request path"},
		{"localhost", "single label is not a lookup target"},
		{"exam ple.com", "space is not valid in a DNS name"},
		{"-bad.example.com", "label starts with a hyphen"},
		{"bad-.example.com", "label ends with a hyphen"},
		{"a..b.com", "empty label"},
		{"日本.example", "non-ASCII must be given as punycode"},
		{"1.2.3.4.5", "numeric last label is a malformed address"},
		{"ftp://example.com", "only http and https are URL indicators"},
		{"http://", "URL with no host"},
		{"deadbeef", "hex but not a hash length"},
		{strings.Repeat("a", 64) + ".com", "label longer than 63 bytes"},
	}

	for _, tc := range tests {
		if got, err := Classify(tc.in); err == nil {
			t.Errorf("Classify(%q) = %+v, want error (%s)", tc.in, got, tc.reason)
		}
	}
}

// A 64-character hex string is a SHA256, never a hostname; a 40-character one
// is a SHA1. This pins the ordering of the shape checks.
func TestHashWinsOverName(t *testing.T) {
	got, err := Classify("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Type != TypeFile {
		t.Errorf("Type = %q, want %q", got.Type, TypeFile)
	}
}

func TestTypesOrdersPrimaryThenAlternate(t *testing.T) {
	name, err := Classify("paypal.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := name.Types(); len(got) != 2 || got[0] != TypeDomain || got[1] != TypeHostname {
		t.Errorf("Types() = %v, want [domain hostname]", got)
	}

	ip, err := Classify("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := ip.Types(); len(got) != 1 || got[0] != TypeIPv4 {
		t.Errorf("Types() = %v, want [IPv4]", got)
	}
}

// The path must be escaped so a URL indicator's own slashes cannot be read as
// path separators. Both %3A and a bare colon are accepted by OTX; what matters
// is that the slashes are escaped.
func TestPathForEscapesURLIndicators(t *testing.T) {
	got, err := Classify("http://example.com/a?b=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	path := got.PathFor(TypeURL)
	if strings.Contains(strings.TrimPrefix(path, "url/"), "/") {
		t.Errorf("PathFor left an unescaped slash in the value: %q", path)
	}
	if !strings.HasPrefix(path, "url/") {
		t.Errorf("PathFor = %q, want it to lead with the type", path)
	}
}

func TestSectionsMatchMeasuredAPI(t *testing.T) {
	// Every type must offer general — it is where pulse_info lives, and the
	// default lookup fetches nothing else.
	for _, tc := range []Type{TypeIPv4, TypeIPv6, TypeDomain, TypeHostname, TypeURL, TypeFile, TypeCVE} {
		if !HasSection(tc, "general") {
			t.Errorf("%s does not offer the general section", tc)
		}
	}
	// A section belonging to another type must not be accepted.
	if HasSection(TypeFile, "passive_dns") {
		t.Error("file wrongly offers passive_dns")
	}
	if HasSection(TypeCVE, "geo") {
		t.Error("cve wrongly offers geo")
	}
	if !HasSection(TypeIPv4, "reputation") {
		t.Error("IPv4 should offer reputation")
	}
	if HasSection(TypeDomain, "reputation") {
		t.Error("domain does not offer reputation upstream")
	}
}

// The default set is what keeps this tool from duplicating its siblings: it
// must be general alone, and general must not be something a sibling owns.
func TestDefaultSectionsAreContextOnly(t *testing.T) {
	got := DefaultSections()
	if len(got) != 1 || got[0] != "general" {
		t.Fatalf("DefaultSections() = %v, want [general]", got)
	}
	if OverlapOwner("general") != "" {
		t.Error("general is claimed by a sibling tool; the default set would duplicate it")
	}
	for _, s := range []string{"reputation", "passive_dns", "malware", "analysis", "url_list"} {
		if OverlapOwner(s) == "" {
			t.Errorf("%s should name the sibling tool that owns it", s)
		}
		for _, d := range got {
			if d == s {
				t.Errorf("%s is owned by %s but is in the default set", s, OverlapOwner(s))
			}
		}
	}
}
