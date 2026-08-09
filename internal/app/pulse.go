package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

func runPulse(args []string, version string, stdout, stderr io.Writer) int {
	var f commonFlags
	var indicators bool
	var limit int
	fs := flag.NewFlagSet("pulse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	f.register(fs)
	fs.BoolVar(&indicators, "indicators", false, "list the indicators the pulse carries")
	fs.IntVar(&limit, "limit", 0, "maximum indicators to list")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "otx-lookup: pulse takes exactly one pulse id")
		return exitError
	}

	cfg, eng, err := f.build(version)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}

	res, err := eng.Pulse(context.Background(), positional[0], engine.PulseOptions{
		Indicators: indicators,
		Limit:      limit,
		Refresh:    f.refresh,
	})
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %s: %v\n", positional[0], err)
		if code := otx.Code(err); code == otx.CodeNotFound || code == otx.CodeBadRequest || code == "" {
			return exitError
		}
		return exitPartial
	}

	if f.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
			return exitError
		}
		return exitOK
	}
	renderPulse(stdout, res, cfg.HasKey(), indicators)
	return exitOK
}

func renderPulse(w io.Writer, res *engine.PulseResult, hasKey, wantIndicators bool) {
	fmt.Fprintf(w, "%s  [%s]\n", res.Name, res.ID)

	meta := []string{"author " + res.Author}
	if res.TLP != "" {
		meta = append(meta, "TLP:"+res.TLP)
	}
	if res.Revision > 0 {
		meta = append(meta, fmt.Sprintf("revision %d", res.Revision))
	}
	if res.Cached {
		meta = append(meta, "cached")
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(meta, "  "))

	if !res.Created.IsZero() {
		fmt.Fprintf(w, "  created %s  modified %s\n",
			res.Created.Format("2006-01-02"), res.Modified.Format("2006-01-02"))
	}
	if res.Description != "" {
		fmt.Fprintf(w, "  %s\n", firstLine(res.Description, 100))
	}

	renderList(w, "adversary", nonEmpty(res.Adversary))
	renderList(w, "malware", res.MalwareFamilies)
	renderList(w, "ATT&CK", res.AttackIDs)
	renderList(w, "industries", res.Industries)
	renderList(w, "targeting", res.TargetedCountries)
	renderList(w, "tags", res.Tags)
	for _, r := range res.References {
		fmt.Fprintf(w, "  reference:  %s\n", r)
	}

	if !wantIndicators {
		fmt.Fprintln(w, "  (pass --indicators to list the indicators this pulse carries)")
		return
	}

	// The count line is the honest part. The detail endpoint reports no total,
	// so without a key the number shown is simply what came back — which may be
	// a page. Saying "unknown" is the only truthful thing available.
	if res.IndicatorsExact {
		fmt.Fprintf(w, "  indicators: %d of %d\n", res.IndicatorsShown, res.IndicatorsHeld)
	} else {
		fmt.Fprintf(w, "  indicators: %d returned; the total is unknown — "+
			"the pulse detail reports none%s\n", res.IndicatorsShown, keyHint(hasKey))
	}
	for _, ind := range res.Indicators {
		date := ""
		if t, ok := otx.ParseTime(ind.Created); ok {
			date = t.Format("2006-01-02")
		}
		state := "active"
		if !ind.Active() {
			state = "inactive"
		}
		fmt.Fprintf(w, "    %-40s %-10s %-10s %-8s %s\n",
			truncate(ind.Indicator, 40), ind.Type, date, state, firstLine(ind.Description, 40))
	}
}

func keyHint(hasKey bool) string {
	if hasKey {
		return " and the paginated endpoint did not answer"
	}
	return ", and the endpoint that does needs an API key"
}

func runSearch(args []string, version string, stdout, stderr io.Writer) int {
	var f commonFlags
	var limit, page int
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	f.register(fs)
	fs.IntVar(&limit, "limit", 0, "results per page (default from config)")
	fs.IntVar(&page, "page", 1, "page number")

	positional, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(positional) == 0 {
		fmt.Fprintln(stderr, "otx-lookup: search needs a query")
		return exitError
	}
	query := strings.Join(positional, " ")

	_, eng, err := f.build(version)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		return exitError
	}

	res, err := eng.Search(context.Background(), query, page, limit)
	if err != nil {
		fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
		if otx.Code(err) == otx.CodeAuthRequired {
			return exitError
		}
		return exitPartial
	}

	if f.jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "otx-lookup: %v\n", err)
			return exitError
		}
		return exitOK
	}

	header := fmt.Sprintf("%q  %d pulses held, %d shown", res.Query, res.Held, res.Shown)
	if res.HasMore {
		header += "  (more pages available)"
	}
	fmt.Fprintln(stdout, header)
	for _, p := range res.Pulses {
		date := "          "
		if !p.Modified.IsZero() {
			date = p.Modified.Format("2006-01-02")
		}
		fmt.Fprintf(stdout, "  %s  %-44s %-16s %s\n", date, truncate(p.Name, 44), p.Author, p.ID)
		if detail := pulseDetail(p); detail != "" {
			fmt.Fprintf(stdout, "              %s\n", detail)
		}
	}
	return exitOK
}

func renderList(w io.Writer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "  %-11s %s\n", label+":", strings.Join(values, ", "))
}

func nonEmpty(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return []string{s}
}

func firstLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return truncate(strings.TrimSpace(s), max)
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
