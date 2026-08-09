package workspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Workspace is a directory an MCP caller supplied, opened as an os.Root so
// every write stays inside it even if a name is crafted to escape.
type Workspace struct {
	root *os.Root
	dir  string
}

// Open creates dir if needed and opens it as a containment root.
func Open(dir string) (*Workspace, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("workspace directory is empty")
	}
	dir = expandHome(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open workspace %s: %w", dir, err)
	}
	return &Workspace{root: root, dir: dir}, nil
}

// Close releases the root handle.
func (w *Workspace) Close() error { return w.root.Close() }

// Dir returns the workspace directory.
func (w *Workspace) Dir() string { return w.dir }

// WriteJSONL writes one JSON value per line and returns the absolute path.
//
// JSON Lines rather than one array: an agent or a shell pipeline can stream it,
// and a partially written file still parses up to its last complete line.
func (w *Workspace) WriteJSONL(name string, records []json.RawMessage) (string, error) {
	safe, err := safeName(name)
	if err != nil {
		return "", err
	}
	f, err := w.root.Create(safe)
	if err != nil {
		return "", fmt.Errorf("create %s in workspace: %w", safe, err)
	}
	defer f.Close()
	for _, rec := range records {
		if _, err := f.Write(append(compact(rec), '\n')); err != nil {
			return "", fmt.Errorf("write %s: %w", safe, err)
		}
	}
	return filepath.Join(w.dir, safe), nil
}

// WriteJSON writes a single indented JSON document and returns its path.
func (w *Workspace) WriteJSON(name string, v any) (string, error) {
	safe, err := safeName(name)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := w.root.Create(safe)
	if err != nil {
		return "", fmt.Errorf("create %s in workspace: %w", safe, err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return "", fmt.Errorf("write %s: %w", safe, err)
	}
	return filepath.Join(w.dir, safe), nil
}

// safeName rejects anything that is not a plain filename. os.Root already
// refuses to follow an escape, but failing on the name gives a caller a clear
// reason instead of an opaque syscall error.
func safeName(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("empty filename")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%q must be a plain filename, without path separators", name)
	}
	if strings.HasPrefix(name, ".") {
		return "", fmt.Errorf("%q must not start with a dot", name)
	}
	return name, nil
}

// compact removes incidental whitespace so one record occupies one line — a
// record carrying a newline would otherwise split into two unparseable lines.
func compact(raw json.RawMessage) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		// Not valid JSON. Write it as a JSON string rather than dropping it or
		// emitting a line that will not parse.
		if b, err := json.Marshal(string(raw)); err == nil {
			return b
		}
		return []byte(`""`)
	}
	return buf.Bytes()
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
