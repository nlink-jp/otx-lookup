# AGENTS.md — otx-lookup

## What this is

A CLI and local MCP server that reads the community reports ("pulses") of the
[LevelBlue Open Threat Exchange](https://otx.alienvault.com/) and attaches
campaign context to an indicator of compromise: adversary, malware family,
ATT&CK technique IDs, targeted industries and countries, tags, and who reported
it when. From a pulse it pivots to the other indicators that pulse carries.

**Why it exists at all**, given that OTX overlaps four sibling tools: every
other lookup in the cybersecurity-series answers "one indicator, one
attribute". `pulse_info` — the campaign the indicator was reported under — has
no other owner in the fleet. That, and not reputation or passive DNS, is the
product. The overlapping sections are shipped off by default for exactly this
reason; see "Key design decisions".

Only a third-party index is read, so **no packet reaches the target under
investigation**, placing this early in a triage next to `rdns-lookup`.

Module path: `github.com/nlink-jp/otx-lookup`.

## Build & test

```bash
make build   # → dist/otx-lookup  (NEVER `go build` directly — it drops the binary in the repo root)
make test    # go test -race -cover ./...   (fully offline)
make e2e     # live tests against the real OTX API (network required)
make check   # lint + test + build-all
```

Go 1.25.0, standard library only — `go.mod` has no `require` block. Shared code
(the release scripts, the sectioned-TOML reader, the `internal/mcp` skeleton)
is vendored from sibling projects rather than imported, matching the series.

## Layout

```
main.go                      Entry point; delegates to internal/app
internal/indicator/          Input validation gate — IPv4/IPv6/domain/hostname/URL/hash/CVE
internal/otx/                Upstream client: indicator sections, pulse detail/related/indicators, search
internal/cache/              Fixed-TTL JSON-file cache, atomic writes
internal/config/             Sectioned-TOML subset + OTX_LOOKUP_* / OTX_API_KEY env
internal/engine/             Shared core: classify, cache, fetch, aggregate campaign context
internal/workspace/          File-mediated MCP output, os.Root contained
internal/app/                CLI shell: subcommand dispatch, flags, text/JSON rendering
internal/mcp/                Zero-dep stdio JSON-RPC 2.0 server + embedded usage.md
e2e/                         Live tests behind the `e2e` build tag
docs/{en,ja}/                RFP (the design record)
```

## Key design decisions

- **The overlapping sections are off by default.** `reputation` (abuse-lookup),
  `passive_dns` (rdns-lookup), `malware`/`analysis` (malware-lookup) and
  `url_list` (urlscan-lookup) are each owned by a sibling that does the job
  better. Emitting them by default would hand the analyst two answers to one
  question with no basis to choose. `--sections` is the escape hatch. Reversing
  this would dissolve the tool's reason to exist.
- **The API key is optional, by measurement not by preference.** All indicator
  sections, `pulses/{id}` and `pulses/{id}/related` answer anonymously; only
  `pulses/{id}/indicators`, `search/pulses` and `pulses/subscribed` return 403.
  So the tool degrades gracefully rather than refusing to start, and
  `--anonymous` exists because a keyed query is recorded against the operator's
  OTX account — an OpSec choice the operator should keep.
- **Pivoting is two-step on purpose.** A one-shot `pivot` that aggregated every
  indicator of every pulse was considered and rejected: the request count grows
  as pulses × pagination, and pulse quality varies enough that automatic
  aggregation would silently import junk. The analyst chooses which pulse to
  trust; that decision point is the design.
- **No SDK dependency.** The official
  [OTX-Go-SDK](https://github.com/AlienVault-OTX/OTX-Go-SDK) (Apache-2.0) was
  last pushed 2021-10-28, has no `go.mod` (GOPATH-era `src/otxapi/` layout),
  and implements only `users/me`, `subscriptions` and `pulses/{id}` — none of
  the indicator endpoints this tool is built on. It is credited as a reference
  in README.md and nothing more.
- **The tool reports claims, never verdicts.** Pulses are community
  submissions. Author, vote counts, `false_positive` and `validation` are
  surfaced as evidence; no "malicious/benign" is computed. Same posture as
  `urlscan-lookup`, which passes urlscan's verdicts through without adding its
  own.
- **Write operations are permanently out of scope**, including `submit_file`
  and `submit_url`: uploading a sample or URL tells a third party what the
  organization is investigating.
- **`base_url` is configurable** because the LevelBlue rebrand is in progress
  and documentation already spans `alienvault.com`, `cybersecurity.att.com`
  and `levelblue.com`. The API host is expected to move.
- **Engine is shared** by the CLI and the MCP server so the two faces cannot
  give different answers for the same indicator.

## Gotchas

These were measured against the live API on 2026-08-09. Re-verify before
trusting any of them a year from now.

- **`domain` and `hostname` are not interchangeable, and picking wrong fails
  silently.** OTX indexes a name's pulses under exactly one of them, but both
  endpoints answer `200` with a well-formed body either way — the wrong one
  simply reports zero pulses. Measured:

  | Name | `domain` | `hostname` |
  |---|---|---|
  | `paypal.com` | 50 pulses | 0 |
  | `bbc.co.uk` | 22 pulses | 0 |
  | `www.bbc.co.uk` | 0 | 50 pulses |
  | `mail.google.com` | 0 | 50 pulses |

  The distinction is registrable-domain versus name-with-a-subdomain — a
  public-suffix question, not a label count (`bbc.co.uk` has three labels and
  is a domain; `mail.google.com` has three and is a hostname). A bundled
  suffix list would rot, so the label count only *orders* the attempts and
  `engine.Lookup` asks the alternate whenever the first returns nothing.
  `gov.uk` — a public suffix — returns `400` from both.
- **An errored type must never be laundered into a clean answer.** This was a
  real defect, caught by a live run: `domain` returned 429 while `hostname`
  answered with zero pulses, and the result read "no community report names
  this indicator" and exited 0. "Nothing reported this" and "we could not ask"
  are identical in the data and opposite in meaning. `Result.Incomplete` and
  `EmptyButUnverified` exist for exactly this, the CLI prints `INCONCLUSIVE`,
  and the run exits non-zero. Do not weaken this.
- **The pulse detail embeds the pulse's indicators, and answers anonymously.**
  `GET /pulses/{id}` returns an `indicators` array of
  `{id, indicator, type, created, title, description, content, is_active,
  expiration}` — numeric id, `is_active` 0/1, `expiration` nullable, and the
  indicator timestamps carry **no fractional seconds** while the pulse's own do.
  This is what makes the campaign pivot work without an API key.
  **But the detail reports no total** — no count, no cursor — so an embedded set
  that stopped early is indistinguishable from a complete one. Hence
  `IndicatorsHeld: -1` / `IndicatorsExact: false` unless the paginated
  key-only endpoint answered. Never print a total the endpoint did not give.
- **The pulse detail is slow, and fails outright for very large pulses.** A
  pulse with ~335,000 indicators timed out; `/pulses/{id}/related` returned a
  504 HTML page. Ordinary development traffic also drew 429s and 500s. Assume
  this endpoint is unreliable and keep the fallbacks.
- **No rate-budget header comes back.** The only OTX-specific response header
  observed is `X-OTX-ACTIVE`. `rdns-lookup` paces on
  `x-ratelimit-remaining`; that option does not exist here, so pacing must be
  counted client-side against the published ceiling (1,000 req/h anonymous,
  10,000 req/h with a key). Sustained probing does hit the ceiling: the 429
  above was produced by ordinary development traffic.
- **Flags must be parsed interleaved with targets.** Go's `flag` package stops
  at the first positional, so a plain `fs.Parse` reads
  `lookup paypal.com --limit 3` as three targets and silently drops the limit.
  `parseInterleaved` parses in rounds instead. This was also caught by a live
  run, not by a unit test.
- **The echoed `type` is not the path type.** A SHA256 lookup under
  `file/<hash>` comes back with `"type": "sha256"`. Never use the response's
  own `type` to decide which endpoint answered.
- **A CVE's `general` has a different top-level shape entirely** (`cvss`,
  `epss`, `exploits`, `products`, `configurations`), which is why only the
  common fields are decoded and the whole body is kept raw.
- **`pulse_info.count` can be a page size, not a total.** `example.com`,
  `www.example.com`, a WannaCry hash and `CVE-2021-44228` all returned exactly
  50 — a suspiciously round number that shows up whenever there are many
  pulses. Never present that count as the true total; report retrieved-vs-held
  the way `rdns-lookup` does.
- **The anonymous/authenticated split is per-endpoint, not per-resource.**
  `pulses/{id}` answers anonymously while `pulses/{id}/indicators` — the same
  pulse — returns 403. Feature detection has to be per call.
- **Sections differ by indicator type** and asking for a section a type does
  not have is a client-side bug, not an upstream one. Measured:
  - IPv4: `general, geo, reputation, url_list, passive_dns, malware, nids_list, http_scans`
  - domain / hostname: `general, geo, url_list, passive_dns, malware, whois, http_scans`
  - file: `general, analysis`
  - url: `general, url_list, http_scans, screenshot`
  - cve: `general, nids_list, malware`

  The `general` response carries its own `sections` array, so the list can be
  read from the response rather than hardcoded.
- **URLs must be percent-encoded into the path** —
  `indicators/url/http%3A%2F%2Fexample.com/general`.
- **OTX is free for non-commercial use only** ([EULA](https://www.levelblue.com/legal/otx-eula-terms)).
  There is no VirusTotal-style prohibition on integrating it into a workflow —
  DirectConnect integrations are what the API is for — but the restriction must
  stay stated in both READMEs, the same treatment `malware-lookup` gives the
  MalwareBazaar / Spamhaus terms.
- **e2e fixtures must be chosen for stability.** Pulses can be edited or
  deleted by their authors, so an indicator picked because its pulses looked
  interesting today is a test that fails next month for no reason of ours.
  Prefer long-standing, widely-reported indicators.

## Status

Phases 1 and 2 complete. Every package is implemented and tested: coverage
77–96%, and the offline suite never touches the network or the developer's real
config. `lookup`, `pulse`, `cache` and the MCP server have been exercised
against the live API, including a full stdio MCP session driven through the
built binary.

**Not verified live: `search_pulses` and the paginated
`/pulses/{id}/indicators`.** Both return 403 without an API key, and no key was
available, so their response shapes come from the published documentation and
are tested only against stubs — the `otx.SearchResults` and `otx.IndicatorPage`
doc comments say so. Everything else in this repository was measured. Set
`OTX_LOOKUP_API_KEY` and re-run `make e2e` to close that gap.

Next: Phase 3 — the live e2e suite, then release. Design record:
[docs/ja/otx-lookup-rfp.ja.md](docs/ja/otx-lookup-rfp.ja.md) (primary),
[docs/en/otx-lookup-rfp.md](docs/en/otx-lookup-rfp.md).
