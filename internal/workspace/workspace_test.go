package workspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONLOneRecordPerLine(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "ws"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	records := []json.RawMessage{
		json.RawMessage("{\n  \"indicator\": \"a.test\"\n}"),
		json.RawMessage(`{"indicator":"b.test"}`),
	}
	path, err := w.WriteJSONL("indicators.jsonl", records)
	if err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 — an embedded newline split a record:\n%s", len(lines), b)
	}
	for i, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("line %d does not parse on its own: %s", i, l)
		}
	}
}

// A record that is not valid JSON must not produce a line that fails to parse:
// one bad record would otherwise poison the whole file for a streaming reader.
func TestWriteJSONLKeepsTheFileParseable(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "ws"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	path, err := w.WriteJSONL("mixed.jsonl", []json.RawMessage{
		json.RawMessage(`{"ok":true}`),
		json.RawMessage(`{not json`),
	})
	if err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	b, _ := os.ReadFile(path)
	for i, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if !json.Valid([]byte(l)) {
			t.Errorf("line %d does not parse: %s", i, l)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "ws"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	path, err := w.WriteJSON("pulse.json", map[string]any{"id": "abc", "n": 2})
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got["id"] != "abc" {
		t.Errorf("round trip lost data: %v", got)
	}
}

// The workspace directory comes from an MCP caller, and the filename is derived
// from data. Neither may be able to reach outside the directory.
func TestNamesCannotEscapeTheWorkspace(t *testing.T) {
	base := t.TempDir()
	w, err := Open(filepath.Join(base, "ws"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	for _, name := range []string{
		"../escaped.jsonl",
		"../../escaped.jsonl",
		"sub/dir.jsonl",
		`..\escaped.jsonl`,
		".hidden",
		"",
	} {
		if _, err := w.WriteJSONL(name, nil); err == nil {
			t.Errorf("WriteJSONL(%q) was allowed", name)
		}
		if _, err := w.WriteJSON(name, map[string]any{}); err == nil {
			t.Errorf("WriteJSON(%q) was allowed", name)
		}
	}

	// Nothing may have appeared outside the workspace.
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "ws" {
			t.Errorf("a write escaped the workspace: %s", e.Name())
		}
	}
}

// A symlink inside the workspace pointing outside must not become a write
// target — this is what os.Root containment buys over a path-prefix check.
func TestSymlinkOutOfTheWorkspaceIsRefused(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "ws")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(base, "outside.jsonl")
	if err := os.Symlink(outside, filepath.Join(dir, "link.jsonl")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	if _, err := w.WriteJSONL("link.jsonl", []json.RawMessage{json.RawMessage(`{"x":1}`)}); err == nil {
		if _, statErr := os.Stat(outside); statErr == nil {
			t.Error("a symlink was followed out of the workspace")
		}
	}
}

func TestOpenCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("Open did not create the directory: %v", err)
	}
	if w.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", w.Dir(), dir)
	}
}

func TestOpenRejectsEmptyDir(t *testing.T) {
	if _, err := Open("   "); err == nil {
		t.Error("an empty workspace directory was accepted")
	}
}
