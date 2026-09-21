package mcp

import "testing"

// TestEveryToolSchemaIsClosed is the arch test organization ADR-021 §10
// requires: every registered tool's input schema sets
// additionalProperties:false, so a client validating arguments against the
// schema refuses a mistyped parameter instead of sending it on.
//
// Both halves of the contract are needed and each is tested: the schema stops
// the typo at the client, and strict decoding stops it here
// (TestUnknownArgumentIsRejected). A schema alone rejects nothing.
//
// The schemas are read off the wire — the tools/list response a client really
// receives — not from the literals, so the closing pass in closeSchemas is
// observed where it has to hold rather than where it is written.
func TestEveryToolSchemaIsClosed(t *testing.T) {
	s, _ := newServer(t, &stubEngine{})
	responses := converse(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if len(responses) == 0 {
		t.Fatal("tools/list produced no response")
	}
	result, _ := responses[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	// Vacuity guard: with an empty list every assertion below passes without
	// having examined anything.
	if len(tools) == 0 {
		t.Fatalf("tools/list advertises no tools, so this test proves nothing: %v", responses[0])
	}
	for _, tl := range tools {
		m, _ := tl.(map[string]any)
		name, _ := m["name"].(string)
		schema, ok := m["inputSchema"].(map[string]any)
		if !ok {
			t.Errorf("tool %q has no object inputSchema", name)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("tool %q: schema type = %v, want object", name, schema["type"])
		}
		if schema["additionalProperties"] != false {
			t.Errorf("tool %q: input schema does not set additionalProperties:false "+
				"(got %v) — a validating client would pass an agent's mistyped "+
				"argument through unnoticed (organization ADR-021 §10)",
				name, schema["additionalProperties"])
		}
	}
}
