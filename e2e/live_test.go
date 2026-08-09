//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/otx-lookup/internal/cache"
	"github.com/nlink-jp/otx-lookup/internal/config"
	"github.com/nlink-jp/otx-lookup/internal/engine"
	"github.com/nlink-jp/otx-lookup/internal/otx"
)

// Fixtures. Chosen for stability, not for interest.
//
// Never assert an exact pulse count: pulses are community submissions that
// appear and vanish daily, and a test pinned to a number becomes a false alarm
// within weeks. What is asserted here is behaviour — that a heavily-reported
// indicator reports pulses at all, that the name fallback resolves, that a
// count is qualified rather than invented.
const (
	// A perennial phishing target. It will not stop being reported.
	reportedDomain = "paypal.com"
	// A registrable domain with three labels: the shape puts `hostname` first,
	// but OTX indexes it under `domain`. This is the fixture for the fallback.
	fallbackDomain = "bbc.co.uk"
	// Log4Shell. Permanently reported.
	reportedCVE = "CVE-2021-44228"
	// WannaCry. A hash that OTX resolves but that carried no pulses when
	// measured — used to exercise the empty path, without asserting emptiness.
	knownHash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e04d4c6b5b8dcb03"
	// A pulse that has existed since 2025 with a small indicator set.
	samplePulse = "693096c1cabeccbc6b3a5def"
)

// newEngine wires the real stack against the real API, with the cache isolated
// in a tempdir so a stale entry cannot mask a regression. The API key is read
// from the environment or the operator's config as usual — these tests are
// about what upstream actually does.
func newEngine(t *testing.T) (*config.Config, *engine.Engine) {
	t.Helper()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	cfg, err := config.Load("", 20*time.Second)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.CacheDir = filepath.Join(t.TempDir(), "cache")
	client := otx.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, cfg.RateCeiling(), "otx-lookup/e2e")
	return cfg, engine.New(cfg, &cache.Store{Dir: cfg.CacheDir}, client)
}

func newClient(t *testing.T) (*config.Config, *otx.Client) {
	t.Helper()
	cfg, err := config.Load("", 20*time.Second)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg, otx.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, cfg.RateCeiling(), "otx-lookup/e2e")
}

func requireKey(t *testing.T, cfg *config.Config) {
	t.Helper()
	if !cfg.HasKey() {
		t.Skip("no API key configured; set OTX_LOOKUP_API_KEY or [api] key to run this")
	}
}

func TestLiveLookupReportedIndicator(t *testing.T) {
	_, e := newEngine(t)
	res, err := e.Lookup(context.Background(), reportedDomain, engine.Options{Limit: 5})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Incomplete {
		t.Fatalf("the lookup could not be completed: %v", res.Degraded)
	}
	if !res.HasPulses() {
		t.Fatalf("%s reported no pulses; either upstream changed or the fixture went stale", reportedDomain)
	}
	if res.Type != string("domain") {
		t.Errorf("type = %q, want domain", res.Type)
	}
	// The whole reason this tool exists: pulses carry campaign context.
	if res.Context.Empty() {
		t.Error("no campaign context was aggregated from any pulse")
	}
	if res.PulsesShown > res.PulsesHeld {
		t.Errorf("shown (%d) exceeds held (%d)", res.PulsesShown, res.PulsesHeld)
	}
	// Upstream pages at 50, so a heavily-reported indicator must come back
	// marked as capped rather than looking complete.
	if res.PulsesHeld >= 50 && !res.Capped {
		t.Errorf("held %d pulses but the result is not marked capped", res.PulsesHeld)
	}
}

// The measurement the anonymous name lookup rests on: OTX indexes a name under
// exactly one of domain/hostname and answers 200 either way, so the wrong guess
// is a silent zero. If upstream ever starts indexing under both, this test is
// how we find out.
func TestLiveNameFallbackResolves(t *testing.T) {
	_, e := newEngine(t)
	res, err := e.Lookup(context.Background(), fallbackDomain, engine.Options{Limit: 1})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Incomplete {
		t.Fatalf("the lookup could not be completed: %v", res.Degraded)
	}
	if !res.HasPulses() {
		t.Fatalf("%s reported no pulses under either type", fallbackDomain)
	}
	if res.Type != "domain" {
		t.Errorf("%s answered as %q; it is a registrable domain", fallbackDomain, res.Type)
	}
	if len(res.TriedTypes) != 2 || res.TriedTypes[0] != "hostname" {
		t.Errorf("TriedTypes = %v; the shape should put hostname first and fall back", res.TriedTypes)
	}
}

func TestLiveCVELookup(t *testing.T) {
	_, e := newEngine(t)
	res, err := e.Lookup(context.Background(), reportedCVE, engine.Options{Limit: 3})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "cve" {
		t.Errorf("type = %q, want cve", res.Type)
	}
	if !res.HasPulses() {
		t.Fatalf("%s reported no pulses", reportedCVE)
	}
	if len(res.Context.AttackIDs) == 0 {
		t.Error("a widely-analysed CVE produced no ATT&CK techniques")
	}
}

// A hash upstream resolves but that carried no pulses when measured. The
// assertion is on the contract, not the count: an answer with no pulses must
// come back conclusive, so it can be trusted as "nobody reported this".
func TestLiveHashLookupIsConclusive(t *testing.T) {
	_, e := newEngine(t)
	res, err := e.Lookup(context.Background(), knownHash, engine.Options{Limit: 1})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if res.Type != "file" {
		t.Errorf("type = %q, want file", res.Type)
	}
	if res.Incomplete || res.EmptyButUnverified() {
		t.Errorf("the result is inconclusive: %v", res.Degraded)
	}
}

// The pulse detail answers anonymously and embeds the indicators. This is what
// makes the campaign pivot work without a key, so it is worth a live check even
// when a key is configured.
func TestLivePulseDetailEmbedsIndicatorsAnonymously(t *testing.T) {
	cfg, _ := newClient(t)
	anon := otx.New(cfg.BaseURL, "", cfg.Timeout, 0, "otx-lookup/e2e")
	e := engine.New(cfg.Anonymous(), &cache.Store{Dir: filepath.Join(t.TempDir(), "c")}, anon)

	res, err := e.Pulse(context.Background(), samplePulse, engine.PulseOptions{Indicators: true})
	if err != nil {
		t.Fatalf("Pulse: %v", err)
	}
	if len(res.Indicators) == 0 {
		t.Fatal("the detail carried no indicators; the anonymous pivot depends on this")
	}
	// Without a key upstream states no total, and the result must say so
	// rather than presenting the returned count as authoritative.
	if res.IndicatorsExact {
		t.Error("an exact total was claimed without the paginated endpoint")
	}
	if res.IndicatorsHeld != -1 {
		t.Errorf("IndicatorsHeld = %d, want -1 when upstream states no total", res.IndicatorsHeld)
	}
}

// The load-bearing measurement behind the anonymous pivot: the detail returns
// the complete indicator set, not a page. If upstream ever starts truncating,
// every anonymous pivot silently becomes partial — and this is the only place
// that would notice.
func TestLiveDetailIsNotTruncated(t *testing.T) {
	cfg, client := newClient(t)
	requireKey(t, cfg)

	detail, err := client.PulseDetail(context.Background(), samplePulse)
	if err != nil {
		t.Fatalf("PulseDetail: %v", err)
	}
	page, err := client.PulseIndicatorPage(context.Background(), samplePulse, 1, 1)
	if err != nil {
		t.Fatalf("PulseIndicatorPage: %v", err)
	}
	if len(detail.Indicators) != page.Count {
		t.Errorf("the detail embedded %d indicators but upstream holds %d — "+
			"the detail is truncating, and every anonymous pivot is now partial",
			len(detail.Indicators), page.Count)
	}
}

// The auth boundary, asserted from both sides. It decides which features work
// without a key, and the whole optional-key design rests on it.
func TestLiveAuthBoundary(t *testing.T) {
	cfg, _ := newClient(t)
	anon := otx.New(cfg.BaseURL, "", cfg.Timeout, 0, "otx-lookup/e2e")

	// Anonymous: indicator sections and pulse detail answer.
	if _, err := anon.General(context.Background(), "domain", reportedDomain); err != nil {
		t.Errorf("indicator general should answer anonymously: %v", err)
	}
	if _, err := anon.Pulse(context.Background(), samplePulse); err != nil {
		t.Errorf("pulse detail should answer anonymously: %v", err)
	}

	// Anonymous: search is refused. The client refuses before the request, so
	// this asserts our own precondition rather than upstream's status.
	if _, err := anon.SearchPulses(context.Background(), "qakbot", 1, 1); otx.Code(err) != otx.CodeAuthRequired {
		t.Errorf("search without a key: code = %q, want %q", otx.Code(err), otx.CodeAuthRequired)
	}
}

// Upstream rejects a malformed indicator with 400, which must map to
// bad_request rather than being reported as an outage.
func TestLiveMalformedIndicatorIsBadRequest(t *testing.T) {
	_, client := newClient(t)
	_, err := client.IndicatorSection(context.Background(), "IPv4", "not-an-ip", "general")
	if err == nil {
		t.Fatal("upstream accepted a malformed IPv4")
	}
	if got := otx.Code(err); got != otx.CodeBadRequest {
		t.Errorf("code = %q, want %q (err: %v)", got, otx.CodeBadRequest, err)
	}
}

func TestLiveAccountValidatesTheKey(t *testing.T) {
	cfg, client := newClient(t)
	requireKey(t, cfg)

	account, err := client.Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v — the configured key may be invalid", err)
	}
	if account.Username == "" {
		t.Error("the account has no username")
	}
	// member_since is a rendered phrase, not a timestamp. If it ever becomes
	// one, the rendering that passes it through needs revisiting.
	if _, ok := otx.ParseTime(account.MemberSince); ok {
		t.Errorf("member_since parsed as a timestamp (%q); it has always been a "+
			"relative phrase, and the CLI prints it verbatim", account.MemberSince)
	}
}

// A rejected key must be distinguishable from an outage, which is the whole
// point of `auth check`.
func TestLiveRejectedKeyIsAuthRequired(t *testing.T) {
	cfg, _ := newClient(t)
	bad := otx.New(cfg.BaseURL, strings.Repeat("0", 64), cfg.Timeout, 0, "otx-lookup/e2e")

	_, err := bad.Account(context.Background())
	if got := otx.Code(err); got != otx.CodeAuthRequired {
		t.Errorf("code = %q, want %q (err: %v)", got, otx.CodeAuthRequired, err)
	}
}

// Upstream sorts search oldest-first by default; the client asks for
// newest-first. If that parameter is ever ignored, results go stale-first again
// and the feature stops being useful.
func TestLiveSearchIsNewestFirst(t *testing.T) {
	cfg, _ := newClient(t)
	requireKey(t, cfg)
	_, e := newEngine(t)

	res, err := e.Search(context.Background(), "qakbot", 1, 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Pulses) < 2 {
		t.Skipf("only %d results; nothing to compare", len(res.Pulses))
	}
	for i := 1; i < len(res.Pulses); i++ {
		prev, cur := res.Pulses[i-1].Modified, res.Pulses[i].Modified
		if prev.IsZero() || cur.IsZero() {
			continue
		}
		if cur.After(prev) {
			t.Errorf("results are not newest-first: %s (%s) precedes %s (%s)",
				res.Pulses[i-1].ID, prev.Format(time.DateOnly), res.Pulses[i].ID, cur.Format(time.DateOnly))
			break
		}
	}
}

// exact_match is documented as a boolean and arrives as a string. Decoding must
// keep working whatever it is — this already broke search once.
func TestLiveSearchDecodesRegardlessOfExactMatch(t *testing.T) {
	cfg, client := newClient(t)
	requireKey(t, cfg)

	res, err := client.Search(context.Background(), "qakbot", 1, 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Count == 0 {
		t.Error("a search for qakbot returned no count")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
