package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the OTX DirectConnect API root. It is a setting rather
	// than a constant in the client because the LevelBlue rebrand is in
	// progress and the host is expected to move.
	DefaultBaseURL = "https://otx.alienvault.com/api/v1"
	// DefaultLimit is how many pulses a lookup lists before summarising the
	// rest. Ten is enough to see whether an indicator belongs to one campaign
	// or to many.
	DefaultLimit = 10
	// DefaultTimeout bounds each HTTPS exchange.
	DefaultTimeout = 30 * time.Second
	// DefaultCacheTTL is how long a cached answer stays fresh. Pulses are
	// edited rarely and a triage revisits the same indicator several times in a
	// session, so a day keeps that down to one request.
	DefaultCacheTTL = 24 * time.Hour
	// DefaultMCPInlineMax is how many records an MCP tool returns inline before
	// switching to a file under workspace_root.
	DefaultMCPInlineMax = 200

	// AnonymousRateCeiling and KeyedRateCeiling are the request budgets OTX
	// publishes. They have to be tracked locally: unlike ip.thc.org, OTX
	// returns no remaining-budget header, so there is nothing to pace on.
	AnonymousRateCeiling = 1000
	KeyedRateCeiling     = 10000
)

// Config holds resolved runtime settings.
type Config struct {
	APIKey       string        // OTX API key; empty means anonymous
	BaseURL      string        // API root
	DefaultLimit int           // pulses listed before the rest are summarised
	CacheDir     string        // result-cache directory
	CacheTTL     time.Duration // how long a cached answer stays fresh
	Timeout      time.Duration // network timeout per exchange
	MaxPerHour   int           // request budget; 0 means "derive from key presence"
	MCPInlineMax int           // MCP records returned inline before spilling to a file
	WorkspaceDir string        // default MCP file-mediated output root
}

// Load resolves configuration. If configPath is empty the default location
// (~/.config/otx-lookup/config.toml) is used when present. Environment
// variables override file values; a non-zero timeoutOverride wins over both.
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{
		BaseURL:      DefaultBaseURL,
		DefaultLimit: DefaultLimit,
		CacheDir:     DefaultCacheDir(),
		CacheTTL:     DefaultCacheTTL,
		Timeout:      DefaultTimeout,
		MCPInlineMax: DefaultMCPInlineMax,
	}

	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	if configPath != "" {
		if f, err := os.Open(configPath); err == nil {
			defer f.Close()
			sections, perr := parseTOML(f)
			if perr != nil {
				return nil, fmt.Errorf("parse config %s: %w", configPath, perr)
			}
			if aerr := applySections(cfg, sections); aerr != nil {
				return nil, fmt.Errorf("config %s: %w", configPath, aerr)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("open config %s: %w", configPath, err)
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}
	return cfg, validate(cfg)
}

// Anonymous returns a copy with the API key removed. This backs --anonymous: a
// query sent with a key is recorded against the operator's OTX account, and
// everything except the pulse indicator list and pulse search answers without
// one, so declining to identify yourself is a supported way to work.
func (c *Config) Anonymous() *Config {
	clone := *c
	clone.APIKey = ""
	return &clone
}

// HasKey reports whether an API key is configured.
func (c *Config) HasKey() bool { return c.APIKey != "" }

// RateCeiling is the hourly request budget this configuration may spend.
func (c *Config) RateCeiling() int {
	if c.MaxPerHour > 0 {
		return c.MaxPerHour
	}
	if c.HasKey() {
		return KeyedRateCeiling
	}
	return AnonymousRateCeiling
}

// Redacted returns the config with the key replaced by a fixed marker, for
// anything that prints or serialises settings. The key is never rendered:
// it carries the whole account's authority, since OTX has no scopes.
func (c *Config) Redacted() Config {
	clone := *c
	if clone.APIKey != "" {
		clone.APIKey = "[set]"
	}
	return clone
}

func validate(cfg *Config) error {
	if cfg.DefaultLimit < 1 {
		return fmt.Errorf("[query] default_limit must be at least 1")
	}
	if cfg.MCPInlineMax < 1 {
		return fmt.Errorf("[mcp] inline_max_records must be at least 1")
	}
	if cfg.MaxPerHour < 0 {
		return fmt.Errorf("[ratelimit] max_per_hour cannot be negative")
	}
	if cfg.BaseURL == "" {
		return fmt.Errorf("[api] base_url must not be empty")
	}
	return nil
}

func applySections(cfg *Config, sections map[string]map[string]string) error {
	if a := sections["api"]; a != nil {
		if v := a["key"]; v != "" {
			cfg.APIKey = v
		}
		if v := a["base_url"]; v != "" {
			cfg.BaseURL = v
		}
	}
	if q := sections["query"]; q != nil {
		if v := q["default_limit"]; v != "" {
			n, err := parseInt(v)
			if err != nil {
				return fmt.Errorf("[query] default_limit: %w", err)
			}
			cfg.DefaultLimit = n
		}
	}
	if c := sections["cache"]; c != nil {
		if v := c["ttl_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[cache] ttl_hours: %w", err)
			}
			cfg.CacheTTL = d
		}
		if v := c["dir"]; v != "" {
			cfg.CacheDir = expandHome(v)
		}
	}
	if n := sections["network"]; n != nil {
		if v := n["timeout_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[network] timeout_seconds: %w", err)
			}
			cfg.Timeout = d
		}
	}
	if r := sections["ratelimit"]; r != nil {
		if v := r["max_per_hour"]; v != "" {
			n, err := parseInt(v)
			if err != nil {
				return fmt.Errorf("[ratelimit] max_per_hour: %w", err)
			}
			cfg.MaxPerHour = n
		}
	}
	if m := sections["mcp"]; m != nil {
		if v := m["inline_max_records"]; v != "" {
			n, err := parseInt(v)
			if err != nil {
				return fmt.Errorf("[mcp] inline_max_records: %w", err)
			}
			cfg.MCPInlineMax = n
		}
		if v := m["workspace"]; v != "" {
			cfg.WorkspaceDir = expandHome(v)
		}
	}
	return nil
}

func applyEnv(cfg *Config) error {
	// OTX_LOOKUP_API_KEY is this tool's own name and wins. OTX_API_KEY is the
	// variable the official OTX SDKs conventionally use, accepted so an
	// environment already set up for them works here unchanged.
	if v := os.Getenv("OTX_LOOKUP_API_KEY"); v != "" {
		cfg.APIKey = v
	} else if v := os.Getenv("OTX_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("OTX_LOOKUP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("OTX_LOOKUP_DEFAULT_LIMIT"); v != "" {
		n, err := parseInt(v)
		if err != nil {
			return fmt.Errorf("OTX_LOOKUP_DEFAULT_LIMIT: %w", err)
		}
		cfg.DefaultLimit = n
	}
	if v := os.Getenv("OTX_LOOKUP_CACHE_DIR"); v != "" {
		cfg.CacheDir = expandHome(v)
	}
	if v := os.Getenv("OTX_LOOKUP_CACHE_TTL_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return fmt.Errorf("OTX_LOOKUP_CACHE_TTL_HOURS: %w", err)
		}
		cfg.CacheTTL = d
	}
	if v := os.Getenv("OTX_LOOKUP_TIMEOUT_SECONDS"); v != "" {
		d, err := parseSeconds(v)
		if err != nil {
			return fmt.Errorf("OTX_LOOKUP_TIMEOUT_SECONDS: %w", err)
		}
		cfg.Timeout = d
	}
	if v := os.Getenv("OTX_LOOKUP_MAX_PER_HOUR"); v != "" {
		n, err := parseInt(v)
		if err != nil {
			return fmt.Errorf("OTX_LOOKUP_MAX_PER_HOUR: %w", err)
		}
		cfg.MaxPerHour = n
	}
	if v := os.Getenv("OTX_LOOKUP_MCP_INLINE_MAX"); v != "" {
		n, err := parseInt(v)
		if err != nil {
			return fmt.Errorf("OTX_LOOKUP_MCP_INLINE_MAX: %w", err)
		}
		cfg.MCPInlineMax = n
	}
	if v := os.Getenv("OTX_LOOKUP_WORKSPACE"); v != "" {
		cfg.WorkspaceDir = expandHome(v)
	}
	return nil
}

func parseInt(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%q is not an integer", v)
	}
	return n, nil
}

func parseSeconds(v string) (time.Duration, error) {
	s, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || s <= 0 {
		return 0, fmt.Errorf("%q is not a positive number", v)
	}
	return time.Duration(s * float64(time.Second)), nil
}

func parseHours(v string) (time.Duration, error) {
	h, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || h <= 0 {
		return 0, fmt.Errorf("%q is not a positive number", v)
	}
	return time.Duration(h * float64(time.Hour)), nil
}

// DefaultConfigPath returns the default config file location, honoring
// XDG_CONFIG_HOME.
func DefaultConfigPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "otx-lookup", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "otx-lookup", "config.toml")
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME. Cached answers are re-fetchable transient state, so they
// belong under the cache home, not data.
func DefaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "otx-lookup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "otx-lookup-cache"
	}
	return filepath.Join(home, ".cache", "otx-lookup")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// parseTOML parses the minimal subset this tool needs: [section] headers and
// key = value lines, where value is an optionally quoted string. Comments start
// with '#'. It intentionally does not support arrays, nested tables, or typed
// values. Vendored from the sibling lookup tools rather than imported, matching
// the series.
func parseTOML(r io.Reader) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := ""
	sections[current] = map[string]string{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "[") {
			end := strings.IndexByte(raw, ']')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(raw[1:end])
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := parseValue(strings.TrimSpace(raw[eq+1:]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		sections[current][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// parseValue strips surrounding quotes, or trims a trailing inline comment from
// a bare value.
func parseValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = strings.TrimSpace(v[:hash])
	}
	return v
}
