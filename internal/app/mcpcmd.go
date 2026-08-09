package app

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/mcp"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// runMCP serves the stdio MCP server until stdin closes. MCP has no
// protocol-level cancel, so a closing stdin is the shutdown signal.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	var configPath string
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")
	if _, err := parseInterleaved(fs, args); err != nil {
		return exitError
	}

	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}
	store := &cache.Store{Dir: cfg.CacheDir}

	srv := &mcp.Server{
		Cfg:     cfg,
		Cache:   store,
		Version: version,
		// An engine per call, because `anonymous: true` has to drop the
		// configured key and the key is baked into the client.
		New: func(anonymous bool) mcp.Engine {
			c := cfg
			if anonymous {
				c = cfg.Anonymous()
			}
			client := otx.New(c.BaseURL, c.APIKey, c.Timeout, c.RateCeiling(), "otx-lookup/"+version)
			return engine.New(c, store, client)
		},
	}

	if err := srv.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "otx-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
