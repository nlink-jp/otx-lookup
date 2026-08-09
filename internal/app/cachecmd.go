package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
)

func runCache(args []string, stdout, stderr io.Writer) int {
	var jsonOut bool
	var configPath string
	fs := flag.NewFlagSet("cache", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.BoolVar(&jsonOut, "json", false, "JSON output")
	fs.BoolVar(&jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "otx-lookup: cache takes one subcommand: status or clear")
		return exitError
	}

	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}
	store := &cache.Store{Dir: cfg.CacheDir}

	switch positional[0] {
	case "status":
		st := store.Stat()
		if jsonOut {
			payload := struct {
				cache.Stats
				TTLHours float64 `json:"ttl_hours"`
			}{Stats: st, TTLHours: cfg.CacheTTL.Hours()}
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(payload); err != nil {
				fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
				return exitError
			}
			return exitOK
		}
		fmt.Fprintf(stdout, "cache: %s\n", st.Dir)
		fmt.Fprintf(stdout, "  entries: %d  (%s)\n", st.Entries, humanBytes(st.Bytes))
		fmt.Fprintf(stdout, "  ttl:     %g hours\n", cfg.CacheTTL.Hours())
		if st.Entries > 0 {
			fmt.Fprintf(stdout, "  written: %s .. %s\n",
				st.Oldest.Format("2006-01-02 15:04"), st.Newest.Format("2006-01-02 15:04"))
			// The TTL is applied when reading, so entries older than it are
			// already dead weight rather than answers still in use.
			fmt.Fprintln(stdout, "  note: the TTL is applied at read time, so lowering it in the")
			fmt.Fprintln(stdout, "        config expires entries already on disk.")
		}
		return exitOK

	case "clear":
		n, err := store.Clear()
		if err != nil {
			fmt.Fprintf(stderr, "otx-lookup: clear cache: %v\n", err)
			return exitError
		}
		if jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"removed": n, "dir": store.Dir}); err != nil {
				fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
				return exitError
			}
			return exitOK
		}
		fmt.Fprintf(stdout, "removed %d cached entr%s from %s\n", n, plural(n, "y", "ies"), store.Dir)
		return exitOK

	default:
		fmt.Fprintf(stderr, "otx-lookup: unknown cache subcommand %q (want status or clear)\n", positional[0])
		return exitError
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
