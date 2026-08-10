# CLAUDE.md — otx-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that attaches **campaign context** to an indicator of
compromise by reading the community reports ("pulses") of the **LevelBlue Open
Threat Exchange** (`https://otx.alienvault.com/api/v1`). Where the sibling
lookup tools each answer "one indicator, one attribute" — `asn-lookup`
(attribution), `whois-lookup` (registration), `abuse-lookup` (reputation),
`rdns-lookup` (relationships), `doh-lookup` (current resolution),
`malware-lookup` (what a hash is), `urlscan-lookup` (how a URL behaves) — this
one answers whether the indicator belongs to a **known campaign**: adversary,
malware family, ATT&CK techniques, targeted industries and countries, reporter
and date. From a pulse it pivots to the other indicators that pulse carries.

Only a third-party index is read, so **no packet reaches the target under
investigation**.

## Build & test

```bash
make build       # → dist/otx-lookup  (never `go build` directly — it drops the binary in the repo root)
make test        # go test -race -cover ./...   (fully offline)
make e2e         # live tests against the real OTX API (network required)
make check       # lint + test + build-all
```

Go 1.25+. **No external dependencies — standard library only.**

## Architecture

```
main.go                 CLI entry: main.version → app.Run
internal/indicator/     Pre-network gate: classify IPv4/IPv6/domain/hostname/URL/hash/CVE
internal/otx/           OTX DirectConnect client (X-OTX-API-KEY header)
internal/cache/         Fixed-TTL JSON-file cache, atomic writes, TTL applied at read time
internal/config/        Sectioned-TOML subset + OTX_LOOKUP_* / OTX_API_KEY resolution
internal/engine/        classify → cache → otx → context aggregation; shared by CLI + MCP
internal/workspace/     Agent-provided output dir + os.Root containment (file-mediated MCP)
internal/app/           Dispatch + lookup/pulse/search/cache/mcp; text and JSON rendering
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 server; embedded get_usage manual
e2e/                    Live tests behind the `e2e` build tag
```

Core logic takes injected dependencies (the HTTP client behind an interface,
the engine's clock and sleep injected) so tests are deterministic and offline.

## Key conventions

- **Overlapping sections are off by default — this is the reason the tool
  fits the shelf.** `reputation`, `passive_dns`, `malware`/`analysis` and
  `url_list` are each owned by a sibling tool. Showing them by default leaves
  the analyst with two answers to one question and no basis to prefer either.
  They are opt-in via `--sections`. Do not promote them to the default set.
- **The API key is optional, and that is load-bearing.** Every indicator
  section, the pulse detail and the pulse related list answer anonymously; a
  key adds only the pulse indicator list, pulse search, and a higher ceiling.
  So the tool must start and work without one (graceful degradation), and
  `--anonymous` must skip a configured key entirely — a query sent with a key
  is recorded against the operator's OTX account.
- **No rate budget comes back from upstream.** Responses carry no
  remaining-quota header (only `X-OTX-ACTIVE` was observed). Unlike
  `rdns-lookup`, which paces on what upstream reports, pacing here must be
  counted client-side against the published ceiling — 1,000 req/h anonymous,
  10,000 req/h with a key.
- **A partial answer is never presented as a complete one.**
  `pulse_info.count` can reflect a page rather than a true total
  (`example.com` returns 50). Always report what upstream holds next to what
  was retrieved. This is the `rdns-lookup` honesty principle and it is not
  optional here.
- **A name is asked as both `domain` and `hostname`.** OTX indexes a name's
  pulses under exactly one of the two and answers 200 either way, so a wrong
  guess reports zero pulses and looks exactly like a clean indicator. The
  label count only orders the attempts; the fallback is what makes it correct.
- **An empty answer built on a failed lookup is never reported as clean.** If
  one type could not be queried, `Result.Incomplete` is set, the CLI prints
  `INCONCLUSIVE`, and the exit code is non-zero. A transient 429 turning into
  "nothing reported this indicator" is the single worst way this tool can be
  wrong — it already happened once, in a live run, before the guard existed.
- **No verdicts.** Pulses are community submissions of varying quality. Surface
  the author, vote counts, `false_positive` and `validation` as evidence; never
  compute "malicious" or "benign". Analysis belongs to the calling agent or
  the analyst.
- **Pivoting is deliberately two-step.** `lookup` shows pulse IDs; `pulse <id>
  --indicators` expands one. A one-shot "aggregate every indicator of every
  pulse" command was rejected: request count grows as pulses × pagination, and
  it would silently mix in indicators from low-quality pulses. Which pulse to
  trust is the analyst's decision and must not be erased.
- **No SDK dependency.** The official OTX-Go-SDK (Apache-2.0) is a reference
  only — last pushed 2021-10-28, no `go.mod`, and it does not implement the
  indicator endpoints at all. Attribution lives in README.md.
- **Write operations are out of scope, permanently.** No pulse create / edit /
  delete, no subscribe / follow, and specifically **no `submit_file` /
  `submit_url`** — uploading a sample or URL tells a third party what the
  organization is looking at.
- **The key is a secret.** Sent only in the `X-OTX-API-KEY` header; never in a
  URL, never logged. `config.toml` is gitignored.
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge.

## Status

Released and integrated. Every endpoint has been measured against the live API,
and the tool runs as a registered MCP server. Design:
[docs/ja/otx-lookup-rfp.ja.md](docs/ja/otx-lookup-rfp.ja.md) (RFP plus its
post-implementation corrections); measured upstream behaviour is in AGENTS.md.

**A tool result must fit in a client's response budget.** `limit` bounds the
pulse list only — the aggregate and references are independent of it, and an
untrimmed lookup of a heavily-analysed CVE reached 162 KB and was refused by the
client. `internal/mcp` caps each ranked category and accounts for every value it
drops. Do not remove that cap, and do not let a new field grow unbounded into a
tool response.

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
