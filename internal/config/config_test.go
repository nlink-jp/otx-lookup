package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points every discovery path at a temp dir and clears the tool's
// environment, so a test never reads the developer's real config or key.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{
		"OTX_LOOKUP_API_KEY", "OTX_API_KEY", "OTX_LOOKUP_BASE_URL",
		"OTX_LOOKUP_DEFAULT_LIMIT", "OTX_LOOKUP_CACHE_DIR", "OTX_LOOKUP_CACHE_TTL_HOURS",
		"OTX_LOOKUP_TIMEOUT_SECONDS", "OTX_LOOKUP_MAX_PER_HOUR",
		"OTX_LOOKUP_MCP_INLINE_MAX", "OTX_LOOKUP_WORKSPACE",
	} {
		t.Setenv(k, "")
	}
	return dir
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestDefaults(t *testing.T) {
	isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, DefaultBaseURL)
	}
	if cfg.DefaultLimit != DefaultLimit {
		t.Errorf("DefaultLimit = %d, want %d", cfg.DefaultLimit, DefaultLimit)
	}
	if cfg.CacheTTL != DefaultCacheTTL {
		t.Errorf("CacheTTL = %v, want %v", cfg.CacheTTL, DefaultCacheTTL)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.HasKey() {
		t.Error("a key appeared from nowhere")
	}
}

func TestFileValuesApplied(t *testing.T) {
	dir := isolate(t)
	path := writeConfig(t, dir, `
# comment
[api]
key = "file-key"
base_url = "https://example.test/api/v1"

[query]
default_limit = 3

[cache]
ttl_hours = 2

[network]
timeout_seconds = 5

[ratelimit]
max_per_hour = 42

[mcp]
inline_max_records = 7
workspace = "/tmp/ws"
`)
	cfg, err := Load(path, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "file-key" {
		t.Errorf("APIKey = %q, want file-key", cfg.APIKey)
	}
	if cfg.BaseURL != "https://example.test/api/v1" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.DefaultLimit != 3 {
		t.Errorf("DefaultLimit = %d, want 3", cfg.DefaultLimit)
	}
	if cfg.CacheTTL != 2*time.Hour {
		t.Errorf("CacheTTL = %v, want 2h", cfg.CacheTTL)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}
	if cfg.MaxPerHour != 42 {
		t.Errorf("MaxPerHour = %d, want 42", cfg.MaxPerHour)
	}
	if cfg.MCPInlineMax != 7 {
		t.Errorf("MCPInlineMax = %d, want 7", cfg.MCPInlineMax)
	}
	if cfg.WorkspaceDir != "/tmp/ws" {
		t.Errorf("WorkspaceDir = %q", cfg.WorkspaceDir)
	}
}

// Precedence: flag > environment variable > config file > built-in default.
func TestPrecedence(t *testing.T) {
	dir := isolate(t)
	path := writeConfig(t, dir, "[api]\nkey = \"file-key\"\n\n[network]\ntimeout_seconds = 5\n")

	t.Setenv("OTX_LOOKUP_API_KEY", "env-key")
	t.Setenv("OTX_LOOKUP_TIMEOUT_SECONDS", "9")

	cfg, err := Load(path, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "env-key" {
		t.Errorf("env did not override file: APIKey = %q", cfg.APIKey)
	}
	if cfg.Timeout != 9*time.Second {
		t.Errorf("env did not override file: Timeout = %v", cfg.Timeout)
	}

	// The flag (timeoutOverride) beats both.
	cfg, err = Load(path, 11*time.Second)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 11*time.Second {
		t.Errorf("flag did not override env: Timeout = %v", cfg.Timeout)
	}
}

// OTX_API_KEY is honoured because the official SDKs use it, but this tool's own
// variable wins when both are set.
func TestKeyEnvAliasAndPriority(t *testing.T) {
	isolate(t)
	t.Setenv("OTX_API_KEY", "sdk-key")
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "sdk-key" {
		t.Errorf("OTX_API_KEY ignored: APIKey = %q", cfg.APIKey)
	}

	t.Setenv("OTX_LOOKUP_API_KEY", "own-key")
	cfg, err = Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "own-key" {
		t.Errorf("OTX_LOOKUP_API_KEY should win over OTX_API_KEY: APIKey = %q", cfg.APIKey)
	}
}

func TestMissingConfigFileIsNotAnError(t *testing.T) {
	dir := isolate(t)
	if _, err := Load(filepath.Join(dir, "absent.toml"), 0); err != nil {
		t.Errorf("a missing config file should fall back to defaults, got: %v", err)
	}
}

func TestInvalidValuesAreRejectedByName(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{"[query]\ndefault_limit = zero\n", "default_limit"},
		{"[query]\ndefault_limit = 0\n", "default_limit"},
		{"[cache]\nttl_hours = -1\n", "ttl_hours"},
		{"[network]\ntimeout_seconds = 0\n", "timeout_seconds"},
		{"[mcp]\ninline_max_records = 0\n", "inline_max_records"},
		{"[api]\nbase_url", "expected key = value"},
	}
	for _, tc := range tests {
		dir := isolate(t)
		path := writeConfig(t, dir, tc.body)
		_, err := Load(path, 0)
		if err == nil {
			t.Errorf("%q: want an error naming %s", tc.body, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %q does not name %s", tc.body, err, tc.want)
		}
	}
}

// --anonymous must produce a config with no key, and must not disturb the one
// it came from — a bulk run mixing keyed and anonymous lookups would otherwise
// silently drop the key partway through.
func TestAnonymousClearsKeyWithoutMutating(t *testing.T) {
	cfg := &Config{APIKey: "secret", BaseURL: DefaultBaseURL, DefaultLimit: 1, MCPInlineMax: 1}
	anon := cfg.Anonymous()
	if anon.HasKey() {
		t.Error("Anonymous() left a key in place")
	}
	if !cfg.HasKey() {
		t.Error("Anonymous() mutated the original config")
	}
	if anon.BaseURL != cfg.BaseURL {
		t.Error("Anonymous() dropped an unrelated setting")
	}
}

func TestRateCeiling(t *testing.T) {
	anon := &Config{}
	if got := anon.RateCeiling(); got != AnonymousRateCeiling {
		t.Errorf("anonymous ceiling = %d, want %d", got, AnonymousRateCeiling)
	}
	keyed := &Config{APIKey: "k"}
	if got := keyed.RateCeiling(); got != KeyedRateCeiling {
		t.Errorf("keyed ceiling = %d, want %d", got, KeyedRateCeiling)
	}
	explicit := &Config{APIKey: "k", MaxPerHour: 50}
	if got := explicit.RateCeiling(); got != 50 {
		t.Errorf("explicit ceiling = %d, want 50", got)
	}
}

// The key carries the whole OTX account's authority, so nothing that renders
// settings may reveal it.
func TestRedactedHidesKey(t *testing.T) {
	cfg := &Config{APIKey: "super-secret-value"}
	if got := cfg.Redacted(); strings.Contains(got.APIKey, "super-secret") {
		t.Errorf("Redacted() leaked the key: %q", got.APIKey)
	}
	if cfg.APIKey != "super-secret-value" {
		t.Error("Redacted() mutated the original config")
	}
	none := &Config{}
	if none.Redacted().APIKey != "" {
		t.Error("Redacted() invented a key where there was none")
	}
}
