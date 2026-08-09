package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutGetRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	want := json.RawMessage(`{"pulse_info":{"count":3}}`)

	if err := s.Put("k.json", want, now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.Get("k.json", now.Add(time.Minute), time.Hour)
	if !ok {
		t.Fatal("Get: miss on a fresh entry")
	}
	if string(got) != string(want) {
		t.Errorf("Get = %s, want %s", got, want)
	}
}

// The TTL is applied when reading, so lowering it in the config expires entries
// that are already on disk.
func TestTTLAppliedAtReadTime(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Unix(1_700_000_000, 0)
	if err := s.Put("k.json", json.RawMessage(`1`), now); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := s.Get("k.json", now.Add(90*time.Minute), 2*time.Hour); !ok {
		t.Error("entry should still be fresh under a 2h TTL")
	}
	if _, ok := s.Get("k.json", now.Add(90*time.Minute), time.Hour); ok {
		t.Error("entry should have expired under a 1h TTL")
	}
}

func TestMissesAreNotErrors(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, ok := s.Get("absent.json", time.Now(), time.Hour); ok {
		t.Error("Get reported a hit for a file that does not exist")
	}
}

// A truncated or hand-edited entry must read as a miss, not crash the lookup.
func TestCorruptEntryReadsAsMiss(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "k.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, ok := s.Get("k.json", time.Now(), time.Hour); ok {
		t.Error("corrupt entry reported as a hit")
	}
	// And it must be overwritable.
	if err := s.Put("k.json", json.RawMessage(`2`), time.Now()); err != nil {
		t.Errorf("Put over a corrupt entry: %v", err)
	}
}

// A keyed answer and an anonymous one are different answers: pulse objects
// carry per-account fields. They must not share a cache slot.
func TestAuthScopeSeparatesKeys(t *testing.T) {
	anon := Key("indicator", "domain", "example.com", "general", AuthScope(false))
	keyed := Key("indicator", "domain", "example.com", "general", AuthScope(true))
	if anon == keyed {
		t.Errorf("anonymous and keyed lookups share the cache key %q", anon)
	}
}

func TestKeyVariesWithEveryPart(t *testing.T) {
	base := Key("indicator", "domain", "example.com", "general", "anon")
	variants := map[string]string{
		"different type":    Key("indicator", "hostname", "example.com", "general", "anon"),
		"different value":   Key("indicator", "domain", "example.org", "general", "anon"),
		"different section": Key("indicator", "domain", "example.com", "geo", "anon"),
		"different kind":    Key("pulse", "domain", "example.com", "general", "anon"),
	}
	for name, got := range variants {
		if got == base {
			t.Errorf("%s produced the same key %q", name, got)
		}
	}
}

// Long or awkward values (URLs, deep hostnames) must still yield a usable
// filename, and distinct inputs must not collide.
func TestKeyHashesUnsafeOrLongInputs(t *testing.T) {
	url := Key("indicator", "url", "https://example.com/a/very/long/path?with=query&and=more", "general", "anon")
	if strings.ContainsAny(url, "/:?&") {
		t.Errorf("key kept characters unsafe in a filename: %q", url)
	}
	if !strings.HasSuffix(url, ".json") {
		t.Errorf("key is missing the .json suffix: %q", url)
	}
	other := Key("indicator", "url", "https://example.com/a/very/long/path?with=query&and=less", "general", "anon")
	if url == other {
		t.Error("two different URLs collided into one cache key")
	}
	if len(url) > 200 {
		t.Errorf("key is too long for a filename: %d bytes", len(url))
	}
}

func TestStatAndClear(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	now := time.Unix(1_700_000_000, 0)

	if got := s.Stat(); got.Entries != 0 {
		t.Errorf("empty cache reports %d entries", got.Entries)
	}
	for _, k := range []string{"a.json", "b.json", "c.json"} {
		if err := s.Put(k, json.RawMessage(`{"x":1}`), now); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	// A non-cache file in the directory must not be counted or removed.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	st := s.Stat()
	if st.Entries != 3 {
		t.Errorf("Entries = %d, want 3", st.Entries)
	}
	if st.Bytes == 0 {
		t.Error("Bytes = 0 for a non-empty cache")
	}
	if st.Dir != dir {
		t.Errorf("Dir = %q, want %q", st.Dir, dir)
	}

	n, err := s.Clear()
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n != 3 {
		t.Errorf("Clear removed %d, want 3", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Error("Clear removed a file it does not own")
	}
}

func TestClearOnMissingDirIsNotAnError(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "never-created")}
	n, err := s.Clear()
	if err != nil {
		t.Errorf("Clear on a missing directory: %v", err)
	}
	if n != 0 {
		t.Errorf("Clear removed %d entries from a missing directory", n)
	}
}

// A crash mid-write must not leave a half-written entry that later reads as a
// valid but truncated result, so writes go through a temp file and a rename.
func TestPutLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	if err := s.Put("k.json", json.RawMessage(`{"x":1}`), time.Now()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("Put left a temp file behind: %s", e.Name())
		}
	}
}
