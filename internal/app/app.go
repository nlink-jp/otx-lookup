// Package app implements the otx-lookup command-line interface: subcommand
// dispatch plus the lookup / pulse / search / cache / mcp commands. Core logic
// lives in the indicator, otx, cache, config, and engine packages; this
// package is the thin I/O shell around them.
package app

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. Finding no pulses is a successful answer — most indicators an
// analyst types have never been reported by anyone — so it is distinct from an
// operational failure.
const (
	exitOK      = 0 // every target was looked up (zero pulses included)
	exitPartial = 1 // an upstream failure prevented some lookups
	exitError   = 2 // usage / validation / configuration error
)

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

// run is Run with injected streams, so dispatch, the version banner and the
// lookup output can be tested without touching the process's own stdio.
func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "lookup":
		return runLookup(rest, version, stdin, stdout, stderr)
	case "pulse":
		return runPulse(rest, version, stdout, stderr)
	case "search":
		return runSearch(rest, version, stdout, stderr)
	case "cache":
		return runCache(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, version, stdin, stdout, stderr)
	case "version", "--version", "-v":
		printVersion(stdout, version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitError
	}
}

// printVersion is the single source of the version banner. `--version` and the
// `version` subcommand must print byte-identical output: a Homebrew formula's
// `brew test` calls `--version`, while humans type `version`, and a formula
// that tests one while the docs teach the other is how a release ships broken.
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "otx-lookup "+version)
	fmt.Fprintln(w, "Data source: LevelBlue Open Threat Exchange (otx.alienvault.com).")
	fmt.Fprintln(w, "API key optional; OTX is free for non-commercial use only.")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `otx-lookup — campaign context for an indicator, from OTX community pulses

Usage:
  otx-lookup <command> [flags] [target...]

Commands:
  lookup <indicator ...>   Pulses and campaign context for an indicator
  pulse <pulse_id>         Pulse detail; --indicators lists what it carries
  search <query>           Search pulses (needs an API key)
  cache status             Show the result-cache state
  cache clear              Clear the result cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

Shared flags:
  --anonymous              Query without the configured API key
  -j, --json               JSON output (JSONL for multiple lookup targets)
  --refresh                Bypass the result cache and re-query
  --timeout <dur>          Network timeout (e.g. 10s; default 30s)
  -c, --config <path>      Config file (default ~/.config/otx-lookup/config.toml)

lookup flags:
  --sections <list>        Fetch sections that are off by default
  --limit <n>              Pulses to show (default 10)
  --input <file>           Read newline-separated targets from a file

pulse flags:
  --indicators             List the indicators the pulse carries
  --limit <n>              Maximum indicators to list

search flags:
  --limit <n>              Results per page
  --page <n>               Page number

The indicator type is detected from its shape: IPv4, IPv6, domain, hostname,
URL, file hash (MD5 / SHA1 / SHA256), or CVE. Bulk input: pass multiple
targets, --input <file>, or pipe them on stdin.

Exit codes:
  0  every target was looked up (zero pulses is a valid answer)
  1  an upstream failure prevented some lookups
  2  error (invalid input, bad configuration, ...)

reputation, passive_dns, malware and url_list are off by default: abuse-lookup,
rdns-lookup, malware-lookup and urlscan-lookup each own one of them, and
duplicating them here would blur which tool's answer to trust. Ask for them
explicitly with --sections when you want OTX's view as a second opinion.

Pulses are community submissions of varying quality, so the author, the vote
counts, the false-positive flag and the validation records are shown alongside
them. This tool reports what was claimed; it never declares an indicator
malicious or benign on its own.

An API key is optional. Without one, every indicator section and the pulse
detail are still reachable — and the detail embeds the pulse's indicators, so
pivoting from a pulse to the rest of a campaign works anonymously too. What a
key adds is the paginated indicator endpoint (the only one that reports how many
indicators a pulse really holds), pulse search, and a higher rate ceiling. Note
that queries made with a key are recorded against your OTX account — use
--anonymous when that matters.
`)
}
