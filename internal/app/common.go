package app

import (
	"flag"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// commonFlags are the flags every command shares, so `--anonymous` and
// `--config` mean the same thing everywhere rather than being re-declared (and
// eventually diverging) per command.
type commonFlags struct {
	anonymous bool
	jsonOut   bool
	refresh   bool
	timeout   time.Duration
	config    string
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.anonymous, "anonymous", false, "query without the configured API key")
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.jsonOut, "j", false, "JSON output (shorthand)")
	fs.BoolVar(&c.refresh, "refresh", false, "bypass the result cache and re-query")
	fs.DurationVar(&c.timeout, "timeout", 0, "network timeout (e.g. 10s)")
	fs.StringVar(&c.config, "config", "", "config file path")
	fs.StringVar(&c.config, "c", "", "config file path (shorthand)")
}

// buildClient resolves configuration and wires the upstream client.
func (c *commonFlags) buildClient(version string) (*config.Config, *otx.Client, error) {
	cfg, err := config.Load(c.config, c.timeout)
	if err != nil {
		return nil, nil, err
	}
	if c.anonymous {
		cfg = cfg.Anonymous()
	}
	return cfg, otx.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, cfg.RateCeiling(), "otx-lookup/"+version), nil
}

// build resolves configuration and wires the engine.
func (c *commonFlags) build(version string) (*config.Config, *engine.Engine, error) {
	cfg, client, err := c.buildClient(version)
	if err != nil {
		return nil, nil, err
	}
	return cfg, engine.New(cfg, &cache.Store{Dir: cfg.CacheDir}, client), nil
}

// parseInterleaved parses flags that appear anywhere among the positional
// arguments, and returns the positionals.
//
// Go's flag package stops at the first non-flag argument, so a plain Parse
// would read `lookup paypal.com --limit 3` as three targets and silently ignore
// the limit. Writing the target first is the natural way to type this, and a
// flag that is quietly dropped is worse than one that is rejected — so parse in
// rounds, taking one positional at a time.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}
