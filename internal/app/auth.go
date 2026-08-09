package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// The four answers `auth check` can give. They are four rather than a pair of
// booleans because "we could not ask" is not "the key is bad" — collapsing them
// is how an outage gets reported as a rejected credential.
const (
	authValid       = "valid"       // upstream accepted the key
	authRejected    = "rejected"    // upstream refused the key
	authUnreachable = "unreachable" // upstream could not be asked
	authAbsent      = "absent"      // no key is configured
)

// authStatus is what `auth check` answers, in JSON form.
type authStatus struct {
	// Status is authoritative; KeyValid is the same fact as a boolean, for
	// callers that only want a yes/no.
	Status        string   `json:"status"`
	KeyConfigured bool     `json:"key_configured"`
	KeyValid      bool     `json:"key_valid"`
	Source        string   `json:"source,omitempty"`
	Username      string   `json:"username,omitempty"`
	UserID        int64    `json:"user_id,omitempty"`
	MemberSince   string   `json:"member_since,omitempty"`
	PulseCount    int      `json:"pulse_count,omitempty"`
	RateCeiling   int      `json:"rate_ceiling"`
	Unlocks       []string `json:"unlocks"`
	Message       string   `json:"message"`
}

// runAuth implements `auth check`.
//
// It exists because no other command can answer "is my key working". The
// indicator endpoints answer anonymously, so a typo'd key still returns 200 and
// the tool still prints "authenticated" — meaning only that a key was sent.
// /users/me is the one endpoint that rejects a bad key outright.
func runAuth(args []string, version string, stdout, stderr io.Writer) int {
	var f commonFlags
	fs := flag.NewFlagSet("auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	f.register(fs)

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 || positional[0] != "check" {
		fmt.Fprintln(stderr, "otx-lookup: auth takes one subcommand: check")
		return exitError
	}

	cfg, client, err := f.buildClient(version)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}

	st := authStatus{
		KeyConfigured: cfg.HasKey(),
		RateCeiling:   cfg.RateCeiling(),
		Unlocks:       []string{"pulse search", "the exact indicator total of a pulse"},
	}
	if f.anonymous {
		st.Source = "--anonymous (any configured key was ignored)"
	}

	// No key: answer locally. Spending a request to be told what we already
	// know would be rude to a free service, and the answer is the same.
	if !cfg.HasKey() {
		st.Status = authAbsent
		st.Message = "no API key is configured. Indicator lookups and pulse details " +
			"still work; pulse search does not. Set [api] key in the config file, " +
			"or OTX_LOOKUP_API_KEY."
		return finishAuth(stdout, stderr, f.jsonOut, st, exitError)
	}

	account, err := client.Account(context.Background())
	if err != nil {
		switch otx.Code(err) {
		case otx.CodeAuthRequired:
			st.Status = authRejected
			st.Message = "the configured API key was rejected by OTX. Check it for a " +
				"typo or a stale value; note that a bad key still lets indicator " +
				"lookups succeed, so this is the only command that catches it."
			return finishAuth(stdout, stderr, f.jsonOut, st, exitError)
		default:
			st.Status = authUnreachable
			st.Message = fmt.Sprintf("could not reach OTX to check the key, so this says "+
				"nothing about whether the key is good: %v", err)
			return finishAuth(stdout, stderr, f.jsonOut, st, exitPartial)
		}
	}

	st.Status = authValid
	st.KeyValid = true
	st.Username = account.Username
	st.UserID = account.UserID
	st.MemberSince = account.MemberSince
	st.PulseCount = account.PulseCount
	st.Message = "the API key is valid."
	return finishAuth(stdout, stderr, f.jsonOut, st, exitOK)
}

func finishAuth(stdout, stderr io.Writer, jsonOut bool, st authStatus, code int) int {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
			return exitError
		}
		return code
	}

	switch st.Status {
	case authValid:
		fmt.Fprintf(stdout, "API key: valid  (account %s", st.Username)
		if st.UserID != 0 {
			fmt.Fprintf(stdout, ", id %d", st.UserID)
		}
		fmt.Fprintln(stdout, ")")
		// member_since is already a rendered phrase ("3344 days ago"), not a
		// date to format.
		if s := strings.TrimSpace(st.MemberSince); s != "" {
			fmt.Fprintf(stdout, "  member since: %s\n", s)
		}
		fmt.Fprintf(stdout, "  rate ceiling: %d requests/hour\n", st.RateCeiling)
		fmt.Fprintf(stdout, "  unlocks:      %s\n", joinAnd(st.Unlocks))
	case authRejected:
		fmt.Fprintln(stdout, "API key: REJECTED")
	case authUnreachable:
		fmt.Fprintln(stdout, "API key: UNKNOWN — the check could not be completed")
	default:
		fmt.Fprintln(stdout, "API key: not configured")
		fmt.Fprintf(stdout, "  rate ceiling: %d requests/hour (anonymous)\n", st.RateCeiling)
	}
	if st.Source != "" {
		fmt.Fprintf(stdout, "  source:       %s\n", st.Source)
	}
	fmt.Fprintf(stdout, "  %s\n", st.Message)
	return code
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		out := ""
		for i, s := range items {
			switch {
			case i == 0:
				out = s
			case i == len(items)-1:
				out += " and " + s
			default:
				out += ", " + s
			}
		}
		return out
	}
}
