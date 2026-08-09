# RFP: otx-lookup

> Generated: 2026-08-09
> Status: Draft

## 1. Problem Statement

Every existing lookup tool in the series (asn-lookup, whois-lookup,
abuse-lookup, rdns-lookup, doh-lookup, tor-exit-lookup,
icloud-relay-lookup, mac-lookup, malware-lookup, urlscan-lookup) answers
"one indicator → one attribute". Attribution, registration, reputation,
relationships, current resolution — each is an isolated fact, and none of
them answers the question a triage actually turns on: **is this indicator
part of a known campaign?**

otx-lookup queries the community reports ("pulses") of the LevelBlue Open
Threat Exchange (OTX) and attaches campaign context to an indicator:
**adversary, malware family, ATT&CK techniques, targeted industries and
countries, and when and by whom it was reported**. It then lets the analyst
**pivot to the related indicators** carried by the same pulse, connecting an
isolated alert to a known campaign picture.

Because it only reads a third-party index, **no packet reaches the target
under investigation** — placing it, like rdns-lookup, among the safe opening
moves of a triage.

The user is myself (nlink-jp security investigation and IR work).

## 2. Functional Specification

### Commands / API Surface

```
otx-lookup lookup <indicator>...     # indicator lookup (type auto-detected)
otx-lookup pulse <pulse_id>          # pulse detail
otx-lookup search <query>            # pulse search (API key required)
otx-lookup cache status|clear        # cache operations
otx-lookup mcp                       # run as an MCP server
otx-lookup --version                 # version (brew test calls this)
```

**Type auto-detection**: IPv4 / IPv6 / domain / hostname / URL / file hash
(32 = MD5, 40 = SHA1, 64 = SHA256) / CVE-\d{4}-\d+. Same "single entry
point, decide from shape and length" approach as malware-lookup.

**Principal flags**:

| Flag | Applies to | Meaning |
|---|---|---|
| `--sections a,b,c` | lookup | explicitly fetch sections that are off by default |
| `--anonymous` | global | query without using the configured API key |
| `--indicators` | pulse | expand the indicator list of a pulse (API key required) |
| `--input FILE` | lookup | bulk input (`-` for stdin) |
| `--limit N` | lookup / search | number of records shown / fetched |
| `--json` | global | machine-readable output (JSONL for multiple targets) |

### Input / Output

**Default human-readable output** is built around `pulse_info`:

- pulse count (always stating what upstream holds against what was retrieved)
- most recent pulses: name / author / created·modified / TLP / indicator_count
- context aggregated across all pulses: adversary, malware_families,
  attack_ids (ATT&CK), industries, targeted_countries, tags
- external URLs from `references` (the route to primary sources)
- the `false_positive` flag and `validation` records

**Off by default**: `reputation`, `passive_dns`, `malware`, `url_list` —
each is owned by abuse-lookup, rdns-lookup, malware-lookup and
urlscan-lookup respectively. Duplicating them by default would blur which
tool's answer to trust. `--sections` fetches them when explicitly wanted.

**Bulk**: multiple arguments / `--input FILE` / stdin. `--json` emits JSONL
for multiple targets. Paced against the rate budget.

**Exit code contract** (following malware-lookup / rdns-lookup):

| Code | Meaning |
|---|---|
| 0 | every target was looked up (zero pulses is a valid answer) |
| 1 | an upstream failure prevented some lookups (what succeeded is printed) |
| 2 | usage error — bad input, bad configuration |

**MCP tools**: `lookup_indicator`, `get_pulse`, `search_pulses`,
`cache_status`, `get_usage`. `get_usage` is canonical (mcp-tactics does not
document parameters). Tool errors are structured JSON `{code, message}`.
Large results such as a pulse's indicator list are written to
`workspace_root` and only the path plus a count summary is returned (same
shape as rdns-lookup's `inline_max_records`).

### Configuration

Sectioned TOML at `~/.config/otx-lookup/config.toml` (macOS also searches
`~/.config`). Precedence: **flag > environment variable > config file >
built-in default**.

| Setting | TOML | Env | Default |
|---|---|---|---|
| API key | `[api] key` | `OTX_LOOKUP_API_KEY` / `OTX_API_KEY` | (none) |
| API root | `[api] base_url` | `OTX_LOOKUP_BASE_URL` | `https://otx.alienvault.com/api/v1` |
| Pulses shown | `[query] default_limit` | `OTX_LOOKUP_DEFAULT_LIMIT` | 10 |
| Cache TTL | `[cache] ttl_hours` | `OTX_LOOKUP_CACHE_TTL_HOURS` | 24 |
| Cache dir | `[cache] dir` | `OTX_LOOKUP_CACHE_DIR` | `~/.cache/otx-lookup` |
| Network timeout | `[network] timeout_seconds` | `OTX_LOOKUP_TIMEOUT_SECONDS` | 30 |
| Rate floor | `[ratelimit] min_remaining` | `OTX_LOOKUP_MIN_REMAINING` | (to be tuned) |
| MCP inline cap | `[mcp] inline_max_records` | `OTX_LOOKUP_MCP_INLINE_MAX` | 200 |
| MCP workspace | `[mcp] workspace` | `OTX_LOOKUP_WORKSPACE` | (none) |

`OTX_API_KEY` is accepted as an alias because the official OTX SDKs
conventionally use that variable name. The key is a secret, so
config.example.toml carries a placeholder only.

### External Dependencies

- **LevelBlue OTX DirectConnect API** (`https://otx.alienvault.com/api/v1`,
  auth header `X-OTX-API-KEY`). The API key is **optional** — indicator
  lookups and pulse details work without one (graceful degradation).
- Go standard library plus the same in-house MCP layer as the sibling lookup
  tools. **The official OTX-Go-SDK is not taken as a dependency** (see §3).

## 3. Design Decisions

### Why Go

The whole cybersecurity-series lookup shelf (asn, whois, abuse, rdns, doh,
tor, relay, mac, malware, urlscan) is Go, sharing one distribution path:
single binary, Developer ID signing plus notarization, homebrew tap. Placing
otx-lookup on the same shelf leaves no reason to change language.

### Not depending on the official OTX-Go-SDK

Measured on 2026-08-09 via `gh api` against
[AlienVault-OTX/OTX-Go-SDK](https://github.com/AlienVault-OTX/OTX-Go-SDK):

| Item | Measured |
|---|---|
| Last push | 2021-10-28 |
| Commits | 15 |
| `go.mod` | absent (GOPATH-era `src/otxapi/` layout) |
| API surface | only `users/me`, `subscriptions`, `pulses/{id}` |
| License | Apache-2.0 |

The last row decides it: **`indicators/*`, the core of this tool, is not
implemented at all**. Taking the dependency would save almost no code while
adding the friction of wiring a non-module package into `go.mod`.

So: **direct REST calls plus an Apache-2.0 inspired-by attribution** — the
same judgement made for splunk-mcp and chrome-pilot-mcp. The type
definitions and the `X-OTX-API-KEY` handling serve as reference.

### Complementarity with existing nlink-jp tools

| Tool | Answers | Relation to otx-lookup |
|---|---|---|
| asn-lookup | attribution (AS, country) | orthogonal |
| whois-lookup | registration | orthogonal |
| abuse-lookup | reputation (AbuseIPDB) | **overlap** — OTX `reputation` off by default |
| rdns-lookup | relationships (DNS index) | **overlap** — OTX `passive_dns` off by default |
| doh-lookup | current resolution | orthogonal |
| malware-lookup | what a hash is | **overlap** — OTX `analysis` off by default |
| urlscan-lookup | URL behaviour | **overlap** — OTX `url_list` off by default |
| **otx-lookup** | **campaign context and related IoCs** | **nothing else covers this** |

Turning the overlaps off by default lets otx-lookup sit on the shelf as the
pulse specialist, with `--sections` as the escape hatch.

### Pivoting is a deliberate two-step

The analyst reads a pulse ID from `lookup`, then expands it with
`pulse <id> --indicators`. A one-shot `pivot` command that aggregates every
indicator of every pulse carrying the input was considered and rejected:

- request count grows unpredictably as pulses × pagination
- pulse quality varies — pulses are community submissions, so automatic
  aggregation silently mixes in indicators from low-quality reports.
  Which pulse to trust is the analyst's call, and that decision point must
  not be erased.

### Explicitly out of scope

- **All write operations** — creating, editing, deleting pulses;
  subscribing/unsubscribing; following/unfollowing users. An investigation
  tool has no reason to hold write access.
- **`submit_file` / `submit_url`** — uploading a sample or URL to a third
  party exposes what the organization is interested in. Not built.
- **STIX 2.1 / CSV export** — STIX generation is already owned by the
  incident-research Skill under ADR-010; feeding it `--json` covers the
  need.
- **Feed synchronization via `pulses/subscribed`** — the original purpose of
  DirectConnect, but that is a "stream IoCs into a SIEM" pipeline, not the
  job of a lookup tool. A separate project if it is ever needed.

## 4. Development Plan

### Phase 1: Core

- `internal/config` (sectioned TOML + env + precedence)
- `internal/cache` (TTL; degraded results are never cached)
- `internal/indicator` (type auto-detection: IPv4/IPv6/domain/hostname/URL/hash/CVE)
- `internal/otx` (REST client: all indicator sections, pulse detail, pulse
  related; tested with `httptest`)
- `internal/engine` (aggregating `pulse_info` into a context summary; written
  as pure functions)
- CLI `lookup` subcommand (`--sections`, `--json`, `--limit`, `--anonymous`,
  bulk input) and the exit-code contract
- unit + integration tests

**Independently reviewable.** At this point the core value — attaching
campaign context to an indicator — is complete.

### Phase 2: Features

- `pulse` subcommand (detail plus `--indicators`; the indicator list needs an
  API key)
- `search` subcommand (API key required)
- `cache status|clear`
- MCP server (`lookup_indicator`, `get_pulse`, `search_pulses`,
  `cache_status`, `get_usage`; file-mediated results; structured errors)
- verify graceful degradation with and without a key on every path

**Independently reviewable.**

### Phase 3: Release

- README.md / README.ja.md / three-layer `docs/{en,ja}` / AGENTS.md /
  CHANGELOG.md / config.example.toml / LICENSE
- e2e against live data (fixtures: an indicator with stable pulses, a clean
  indicator with zero pulses, an indicator carrying `false_positive`)
- `make build-all` → signing + notarization → GitHub release
- Integration: cybersecurity-series submodule / org profile /
  nlink-web-site (EN + JA) / homebrew-tap formula /
  **mcp-tactics Skill update (19 → 20 servers — not just adding a row, but
  re-deriving the endpoints of the ranking)** / `check-org.sh` all green

## 5. Required API Scopes / Permissions

- **OAuth scopes / IAM roles: none.**
- A single LevelBlue OTX API key (from the account settings of a free
  otx.alienvault.com account). OTX has no scope concept; the key carries the
  account's full authority.
- **The key is optional.** Without it, all `indicators/*` sections plus
  `pulses/{id}` and `pulses/{id}/related` are reachable anonymously. A key
  unlocks exactly three things — `pulses/{id}/indicators`, `search/pulses`,
  `pulses/subscribed` — and a higher rate ceiling.

## 6. Series Placement

Series: **cybersecurity-series**

Reason: it is a threat-intelligence lookup tool, fitting the same shelf and
the same shape (Go, CLI + MCP, single binary, tap distribution) as the
existing lookup family. util-series is the shelf for general-purpose data
transformation CLIs and addresses a different audience.

## 7. External Platform Constraints

**Measured live on 2026-08-09**:

- **Rate limits**: 1,000 req/h anonymous, 10,000 req/h with an API key.
  **No rate-budget headers come back** (the only OTX header observed was
  `X-OTX-ACTIVE`). Unlike rdns-lookup, remaining budget cannot be read from
  upstream, so **the client must count and pace on its own**.
- **Anonymous / authenticated boundary**:

  | Endpoint | Anonymous |
  |---|---|
  | `indicators/{type}/{ind}/{section}`, all sections | 200 |
  | `pulses/{id}` | 200 |
  | `pulses/{id}/related` | 200 |
  | `pulses/{id}/indicators` | **403** |
  | `search/pulses` | **403** |
  | `pulses/subscribed` | **403** |

- **Sections by indicator type**:

  | Type | Sections |
  |---|---|
  | IPv4 | general, geo, reputation, url_list, passive_dns, malware, nids_list, http_scans |
  | domain / hostname | general, geo, url_list, passive_dns, malware, whois, http_scans |
  | file | general, analysis |
  | url | general, url_list, http_scans, screenshot |
  | cve | general, nids_list, malware |

- **`pulse_info.count` can be capped** — `example.com` returned count = 50,
  which most likely reflects a page size rather than the true total.
  Following rdns-lookup's honesty principle, **always state what upstream
  holds against what was retrieved** so a partial answer is never mistaken
  for a complete one.
- **Pulse quality varies** — these are community submissions, so the author,
  vote counts, `false_positive` and `validation` are surfaced as evidence for
  the analyst. The tool never declares "malicious" or "benign" on its own.
- **The EULA is non-commercial** — "OTX is free to end users for
  non-commercial use". There is no VirusTotal-style prohibition on workflow
  integration (DirectConnect integrations are officially encouraged), but the
  **non-commercial restriction must be stated in the README**, the same
  treatment as malware-lookup's MalwareBazaar / Spamhaus note.
- **The LevelBlue rebrand is in progress** — documentation is scattered
  across `alienvault.com`, `cybersecurity.att.com` and `levelblue.com`. The
  API host `otx.alienvault.com` is still live, but **`base_url` is kept
  configurable** against a future migration.

---

## Discussion Log

**2026-08-09**

1. **Origin** — the user pointed at OTX-Go-SDK and proposed "a CLI + MCP
   server that investigates using OTX data, taking that code as reference".

2. **Evaluating the SDK** — measured with `gh api`: last push 2021-10-28, no
   `go.mod`, only three endpoint groups implemented and `indicators/*`
   missing. Decision: **direct REST, not a dependency**; Apache-2.0 allows an
   inspired-by attribution.

3. **Probing the API** — every endpoint was called anonymously to establish
   the auth boundary, the sections per type, the `pulse_info` shape, and the
   rate limits. The finding that **all indicator sections are reachable
   anonymously** became the basis for making the API key optional.

4. **Narrowing the reason to exist** — OTX's `reputation`, `passive_dns`,
   `malware` and `url_list` collide head-on with four existing tools, while
   `pulse_info` (adversary, malware_families, attack_ids, industries,
   targeted_countries) **has no other owner**. So the tool is positioned as a
   **context-and-pivot** tool rather than a reputation tool, with the
   overlapping sections off by default behind `--sections`.

5. **Scope options** — (a) lookup only, (b) context + pivot, (c) everything.
   **(b) was chosen.**

6. **API key handling** — required vs optional. Since the probes showed the
   core function works anonymously, **optional (graceful degradation)** was
   chosen, matching malware-lookup's MalwareBazaar key. Additionally, because
   using a key ties queries to an OTX account record, **`--anonymous`** was
   added for deliberately unattributed lookups.

7. **Pivot design** — a one-shot `pivot` was considered and rejected: request
   count grows as pulses × pagination, and since pulse quality varies,
   **which pulse to trust is the analyst's judgement**. Hence the deliberate
   two-step (`lookup` → `pulse <id> --indicators`).

8. **Bulk input** — adopted in the same shape as rdns-lookup (`--input` /
   stdin). The generous 10,000 req/h ceiling makes it practical.

9. **Export formats** — STIX 2.1 and CSV were considered; **text + JSON
   only**. STIX generation already belongs to the incident-research Skill
   under ADR-010 and connects via `--json`, so the roles are kept separate.

10. **OpSec positioning** — reading a third-party index sends no packet to the
    target, placing it at **tier 2 (third-party query)** in the mcp-tactics
    four-tier doctrine. The caveat that **an API key ties the query to an OTX
    account record** should be weighed when re-deriving the ranking endpoints
    during the fleet update (19 → 20 servers).
