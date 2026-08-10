package mcp

import (
	"strings"
	"testing"

	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// These are meta-tests: they pin the embedded manual to the code. The
// mcp-tactics skill documents no parameters by design, so usage.md is what an
// agent reads before its first call — a manual that drifts from the
// implementation is worse than none, because it is trusted.

func TestUsageDocumentsEveryTool(t *testing.T) {
	doc := UsageDoc()
	for _, tool := range toolDefinitions() {
		name := tool["name"].(string)
		if !strings.Contains(doc, name) {
			t.Errorf("usage.md never mentions the tool %q", name)
		}
	}
}

func TestUsageDocumentsEveryArgument(t *testing.T) {
	doc := UsageDoc()
	for _, tool := range toolDefinitions() {
		name := tool["name"].(string)
		schema, ok := tool["inputSchema"].(map[string]any)
		if !ok {
			t.Errorf("%s has no inputSchema", name)
			continue
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		for arg := range props {
			if !strings.Contains(doc, arg) {
				t.Errorf("usage.md never mentions %s's argument %q", name, arg)
			}
		}
	}
}

func TestUsageDocumentsEveryErrorCode(t *testing.T) {
	doc := UsageDoc()
	codes := []string{
		CodeInvalidArgument,
		otx.CodeBadRequest,
		otx.CodeAuthRequired,
		otx.CodeNotFound,
		otx.CodeRateLimited,
		otx.CodeUpstream,
		otx.CodeNetwork,
		otx.CodeDecode,
	}
	for _, c := range codes {
		if !strings.Contains(doc, c) {
			t.Errorf("usage.md has no recovery guidance for the error code %q", c)
		}
	}
}

// The two facts that stop an agent from misreading a result: an empty answer is
// normal, and an incomplete one is not an answer at all.
func TestUsageExplainsHowToReadAnEmptyResult(t *testing.T) {
	doc := UsageDoc()
	for _, phrase := range []string{"incomplete", "not an error", "pulses_held", "pulses_shown"} {
		if !strings.Contains(doc, phrase) {
			t.Errorf("usage.md does not explain %q", phrase)
		}
	}
}

// The reason this server exists is that it does not duplicate its siblings. If
// the manual stops saying so, an agent will ask it for reputation data.
func TestUsageExplainsTheDivisionOfLabour(t *testing.T) {
	doc := UsageDoc()
	for _, sibling := range []string{"abuse-lookup", "rdns-lookup", "malware-lookup", "urlscan-lookup"} {
		if !strings.Contains(doc, sibling) {
			t.Errorf("usage.md does not name %s as the owner of an omitted section", sibling)
		}
	}
}

// Every tool's description must survive as a sentence an agent can act on.
func TestToolDescriptionsAreSubstantial(t *testing.T) {
	for _, tool := range toolDefinitions() {
		name := tool["name"].(string)
		desc, _ := tool["description"].(string)
		if len(desc) < 40 {
			t.Errorf("%s has a description too short to be useful: %q", name, desc)
		}
	}
}

// Required arguments must exist in the schema's properties, or a client will
// advertise an argument the server does not accept.
func TestRequiredArgumentsAreDeclared(t *testing.T) {
	for _, tool := range toolDefinitions() {
		name := tool["name"].(string)
		schema := tool["inputSchema"].(map[string]any)
		required, _ := schema["required"].([]string)
		props, _ := schema["properties"].(map[string]any)
		for _, r := range required {
			if _, ok := props[r]; !ok {
				t.Errorf("%s requires %q but does not declare it", name, r)
			}
		}
	}
}

// The quality caveat has to survive in the places an agent actually reads.
//
// A model may act on `tools/list` alone without ever calling `get_usage`, and
// for this data source "who wrote this and how much do I trust it" is the
// single most consequential thing to know — a pulse hit is not a verdict. So it
// is pinned in the server instructions, in the manual, and in the description
// of every tool that returns pulse-derived content.
func TestSourceQualityCaveatIsEverywhereAnAgentLooks(t *testing.T) {
	if !strings.Contains(instructions, "SOURCE QUALITY IS NOT UNIFORM") {
		t.Error("the server instructions do not warn that source quality varies")
	}
	if !strings.Contains(instructions, "claims, not conclusions") {
		t.Error("the server instructions do not say the server returns claims rather than verdicts")
	}

	// Single words, not phrases: the manual is hard-wrapped, so a phrase test
	// would fail on a reflow rather than on a change of meaning.
	doc := UsageDoc()
	for _, word := range []string{"uneven", "corroboration", "indicator_count", "verdicts"} {
		if !strings.Contains(doc, word) {
			t.Errorf("usage.md no longer explains %q", word)
		}
	}

	// Every tool that hands back what somebody else wrote must carry the
	// caveat in its own description, because that is all a `tools/list` reader
	// gets.
	pulseDerived := map[string]bool{
		ToolLookupIndicator: true,
		ToolGetPulse:        true,
		ToolSearchPulses:    true,
	}
	for _, tool := range toolDefinitions() {
		name := tool["name"].(string)
		if !pulseDerived[name] {
			continue
		}
		desc := tool["description"].(string)
		if !mentionsQuality(desc) {
			t.Errorf("%s's description does not caution about source quality: %q", name, desc)
		}
	}
}

// mentionsQuality is deliberately loose about wording and strict about the
// idea: the description has to tell the reader that what comes back was
// written by someone whose care is unknown.
func mentionsQuality(desc string) bool {
	for _, marker := range []string{"uneven", "community submissions", "feed dump", "not evidence", "not a verdict", "never treat a hit as a verdict"} {
		if strings.Contains(desc, marker) {
			return true
		}
	}
	return false
}
