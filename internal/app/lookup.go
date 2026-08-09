package app

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

func runLookup(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	var f commonFlags
	var sections, input string
	var limit int
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	f.register(fs)
	fs.StringVar(&sections, "sections", "", "comma-separated extra sections to fetch")
	fs.IntVar(&limit, "limit", 0, "pulses to list (default from config)")
	fs.StringVar(&input, "input", "", "read newline-separated targets from a file (- for stdin)")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}

	targets, err := readTargets(positional, input, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "otx-lookup: no targets given")
		usage(stderr)
		return exitError
	}

	cfg, eng, err := f.build(version)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}

	opts := engine.Options{Sections: splitList(sections), Limit: limit, Refresh: f.refresh}
	multiple := len(targets) > 1

	// Exit-code accounting. An invalid target is the operator's own mistake and
	// is worth a louder code than an upstream outage, so it wins when both
	// happen in one run.
	badInput, upstreamFailed, answered := false, false, false

	for _, target := range targets {
		res, err := eng.Lookup(context.Background(), target, opts)
		if err != nil {
			fmt.Fprintf(stderr, "otx-lookup: %s: %v\n", target, err)
			if code := otx.Code(err); code == "" || code == otx.CodeBadRequest {
				badInput = true
			} else {
				upstreamFailed = true
			}
			continue
		}
		answered = true
		// An answer assembled from a partial fetch is still worth printing,
		// but the run must not exit 0: a caller scripting on the exit code
		// would otherwise treat an unverified "no pulses" as a clean verdict.
		if res.Incomplete {
			upstreamFailed = true
		}
		if f.jsonOut {
			if err := writeJSON(stdout, res, multiple); err != nil {
				fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
				return exitError
			}
		} else {
			renderText(stdout, res, cfg, multiple)
		}
	}

	switch {
	case badInput:
		return exitError
	case upstreamFailed && answered:
		return exitPartial
	case upstreamFailed:
		return exitPartial
	default:
		return exitOK
	}
}

// readTargets collects targets from arguments, a file, or stdin. Piping is
// supported because triage input arrives as a column of a CSV far more often
// than as one indicator typed by hand.
func readTargets(args []string, input string, stdin io.Reader) ([]string, error) {
	targets := append([]string(nil), args...)

	switch {
	case input == "-":
		lines, err := readLines(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		targets = append(targets, lines...)
	case input != "":
		f, err := os.Open(input)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", input, err)
		}
		defer func() { _ = f.Close() }()
		lines, err := readLines(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", input, err)
		}
		targets = append(targets, lines...)
	case len(targets) == 0 && stdin != nil && !isTerminal(stdin):
		lines, err := readLines(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		targets = append(targets, lines...)
	}
	return targets, nil
}

// isTerminal reports whether the reader is an interactive terminal, in which
// case waiting on it would hang instead of reading piped input.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func readLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w io.Writer, res *engine.Result, multiple bool) error {
	enc := json.NewEncoder(w)
	if !multiple {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(res)
}

// renderText writes the human-readable form. Every result states what upstream
// holds against what was retrieved, so a partial answer can never be mistaken
// for a complete one.
func renderText(w io.Writer, res *engine.Result, cfg *config.Config, multiple bool) {
	if multiple {
		fmt.Fprintln(w)
	}

	held := fmt.Sprintf("%d pulse", res.PulsesHeld)
	if res.PulsesHeld != 1 {
		held += "s"
	}
	line := fmt.Sprintf("%s  [%s]  %s", res.Query, res.Type, held)
	if res.PulsesShown != res.PulsesHeld {
		line += fmt.Sprintf(" held, %d shown", res.PulsesShown)
	}
	if res.Capped {
		line += "  CAPPED"
	}
	fmt.Fprintln(w, line)

	auth := "anonymous"
	if cfg.HasKey() {
		auth = "authenticated"
	}
	provenance := fmt.Sprintf("  source: otx.alienvault.com (%d request", res.Requests)
	if res.Requests != 1 {
		provenance += "s"
	}
	provenance += ", " + auth
	if res.Cached {
		provenance += ", cached"
	}
	provenance += ")"
	fmt.Fprintln(w, provenance)

	if len(res.TriedTypes) > 1 {
		fmt.Fprintf(w, "  resolved: asked as %s; %s answered\n", strings.Join(res.TriedTypes, ", then "), res.Type)
	}

	if !res.HasPulses() {
		if res.EmptyButUnverified() {
			// "Nothing reported this" and "we could not ask" look identical in
			// the data. Saying which one this is, is the whole job here.
			fmt.Fprintln(w, "  INCONCLUSIVE: no pulses found, but a lookup failed — this is not a clean result")
		} else {
			fmt.Fprintln(w, "  no community report names this indicator")
		}
		renderValidation(w, res)
		renderDegraded(w, res)
		renderSections(w, res)
		return
	}

	c := res.Context
	if !c.FirstReported.IsZero() {
		fmt.Fprintf(w, "  reported: %s .. %s\n",
			c.FirstReported.Format("2006-01-02"), c.LastReported.Format("2006-01-02"))
	}
	renderCounted(w, "adversary", c.Adversaries)
	renderCounted(w, "malware", c.MalwareFamilies)
	renderCounted(w, "ATT&CK", c.AttackIDs)
	renderCounted(w, "industries", c.Industries)
	renderCounted(w, "targeting", c.TargetedCountries)
	renderCounted(w, "tags", c.Tags)
	if c.Empty() {
		fmt.Fprintln(w, "  context:   none — the pulses carry no adversary, family, or technique")
	}

	renderValidation(w, res)

	fmt.Fprintln(w, "  pulses:")
	for _, p := range res.Pulses {
		date := "          "
		if !p.Modified.IsZero() {
			date = p.Modified.Format("2006-01-02")
		}
		name := p.Name
		if len(name) > 44 {
			name = name[:41] + "..."
		}
		fmt.Fprintf(w, "    %s  %-44s %-16s %s\n", date, name, p.Author, p.ID)
		if detail := pulseDetail(p); detail != "" {
			fmt.Fprintf(w, "                %s\n", detail)
		}
	}

	if res.Capped {
		fmt.Fprintf(w, "  note: upstream reports %d pulses and returns them a page at a time; "+
			"the true total may be higher\n", res.PulsesHeld)
	}
	if n := len(res.References); n > 0 {
		fmt.Fprintf(w, "  references: %d (see --json for the list)\n", n)
	}
	renderDegraded(w, res)
	renderSections(w, res)
}

func pulseDetail(p engine.PulseSummary) string {
	var parts []string
	if p.Adversary != "" {
		parts = append(parts, "adversary "+p.Adversary)
	}
	if len(p.MalwareFamilies) > 0 {
		parts = append(parts, "malware "+strings.Join(p.MalwareFamilies, "/"))
	}
	if len(p.AttackIDs) > 0 {
		parts = append(parts, "ATT&CK "+strings.Join(attackIDsOnly(p.AttackIDs), ","))
	}
	if p.TLP != "" {
		parts = append(parts, "TLP:"+p.TLP)
	}
	if p.IndicatorCount > 0 {
		parts = append(parts, fmt.Sprintf("%d indicators", p.IndicatorCount))
	}
	return strings.Join(parts, "  ")
}

// attackIDsOnly shortens "T1041 - Exfiltration Over C2 Channel" to "T1041" for
// the per-pulse line; the full labels are in the aggregate above and in --json.
func attackIDsOnly(labels []string) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		if id, _, ok := strings.Cut(l, " - "); ok {
			out = append(out, id)
		} else {
			out = append(out, l)
		}
	}
	return out
}

func renderCounted(w io.Writer, label string, values []engine.Counted) {
	if len(values) == 0 {
		return
	}
	const max = 6
	shown := values
	extra := 0
	if len(shown) > max {
		extra = len(shown) - max
		shown = shown[:max]
	}
	parts := make([]string, 0, len(shown))
	for _, v := range shown {
		parts = append(parts, fmt.Sprintf("%s (%d)", v.Value, v.Pulses))
	}
	line := strings.Join(parts, ", ")
	if extra > 0 {
		line += fmt.Sprintf(", +%d more", extra)
	}
	fmt.Fprintf(w, "  %-11s %s\n", label+":", line)
}

// renderValidation surfaces upstream's own doubt and community false-positive
// reports. This tool reports claims rather than verdicts, and a claim that an
// indicator is benign is evidence too.
func renderValidation(w io.Writer, res *engine.Result) {
	for _, v := range res.Validation {
		msg := v.Message
		if msg == "" {
			msg = v.Name
		}
		fmt.Fprintf(w, "  ! upstream validation: %s (%s)\n", msg, v.Source)
	}
	if res.FalsePositiveReports > 0 {
		fmt.Fprintf(w, "  ! false-positive reports: %d (see --json for detail)\n", res.FalsePositiveReports)
	}
}

// renderDegraded lists everything that could not be fetched — a failed side
// section, or a whole indicator type. Both belong in the output: a result that
// hides what it could not reach is a result that cannot be trusted.
func renderDegraded(w io.Writer, res *engine.Result) {
	for _, d := range res.Degraded {
		fmt.Fprintf(w, "  ! unavailable: %s\n", d)
	}
}

func renderSections(w io.Writer, res *engine.Result) {
	if len(res.Sections) == 0 {
		return
	}
	names := make([]string, 0, len(res.Sections))
	for k := range res.Sections {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Fprintf(w, "  sections fetched: %s (see --json for the bodies)\n", strings.Join(names, ", "))
}
