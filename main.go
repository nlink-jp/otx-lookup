// Command otx-lookup attaches campaign context to an indicator of compromise
// by reading the community reports ("pulses") of the LevelBlue Open Threat
// Exchange, as a CLI and a local MCP server. Where the sibling lookup tools
// answer "one indicator, one attribute" — attribution (asn-lookup),
// registration (whois-lookup), reputation (abuse-lookup), relationships
// (rdns-lookup), current resolution (doh-lookup), what a hash is
// (malware-lookup), how a URL behaves (urlscan-lookup) — this one answers
// whether the indicator is part of a known campaign: which adversary, malware
// family, ATT&CK techniques, targeted industries and countries it was reported
// under, by whom, and when. From there it pivots to the other indicators the
// same pulse carries.
//
// Only a third-party index is read, so no packet reaches the target under
// investigation. The API key is optional: every indicator section and the
// pulse detail are reachable anonymously.
package main

import (
	"os"

	"github.com/nlink-jp/otx-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
