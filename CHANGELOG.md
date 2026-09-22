# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).
- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.

## [0.2.1] - 2026-09-21

### Fixed

- Every MCP tool schema now sets `additionalProperties: false`, as
  organization ADR-021 §10 requires. A validating client refuses a mistyped
  argument instead of forwarding it; the server already decoded strictly, so
  the two halves of the contract now agree. Applied as one pass over the tool
  list (`closeSchemas`) rather than per literal, so a tool added later cannot
  omit it, and pinned by `TestEveryToolSchemaIsClosed` reading the schemas
  back off `tools/list`.

## [0.2.0] - 2026-08-31

### Changed

- **Every MCP result is returned inline.** The server no longer writes files,
  owns no output directory, and takes no `workspace_root`: it works unchanged
  against a client that has no filesystem of its own. Gone from the schemas are
  `lookup_indicator.workspace_root` and `get_pulse.workspace_root`, and from the
  results `pulses_file`, `pulses_in_file`, `full_result_file`, `indicators_file`
  and `indicators_in_file`.
- The aggregate trim stays — a lookup of a heavily-analysed CVE is mostly
  scraped tags — but it is now escapable without a file: `lookup_indicator`
  takes `context_top` and `references_top` (default 25, `-1` for no cap), so
  the tail it holds back is always reachable in the same result.

### Added

- `get_pulse` takes `page`, so a feed-dump pulse's indicators can be walked with
  `limit` + `page` instead of spilled to a file. `indicators_held` is the total.

### Removed

- `[mcp] inline_max_records` / `OTX_LOOKUP_MCP_INLINE_MAX` and `[mcp] workspace`
  / `OTX_LOOKUP_WORKSPACE`. There is no inline threshold left to configure.

## [0.1.2] - 2026-08-10

### Changed

- **The uneven quality of the source is now stated where an agent actually
  reads.** A model can act on `tools/list` alone without ever calling
  `get_usage`, and for this data source "who wrote this, and how much of it
  should I believe" is the most consequential thing to know. The warning now
  appears in the server instructions, in each pulse-derived tool's own
  description, in the CLI help, and — with the field-level detail — in the
  manual. A meta-test pins it in all four so it cannot be quietly dropped.

  The manual now shows what was actually observed in a single lookup rather
  than warning in the abstract: an `adversary` holding a pasted paragraph, a
  `tag` holding an MD5, a `reference` holding an empty string, an `industries`
  entry holding a comma-separated list as one value. The practical guidance is
  concrete too — read the `pulses` count beside each aggregated value as its
  corroboration, and use a pulse's `indicator_count` to tell an analysis from
  an automated feed dump.

## [0.1.1] - 2026-08-10

### Fixed

- `lookup_indicator` could return a result no MCP client would accept. `limit`
  caps the pulse list but bounds neither the aggregated `context` nor
  `references`, so a live call on `CVE-2021-44228` with `limit: 3` produced a
  162 KB result — 63 KB of it 1,705 tags, mostly scraped noise from feed-dump
  pulses — and the client refused it outright. The tool was unusable for
  precisely the indicators most worth looking at.

  Each `context` category is now capped at its top 25 and `references` at 25.
  The categories are ranked by how many pulses named each value, so what is
  dropped is the least-corroborated tail. Nothing is dropped silently:
  `context_omitted`, `references_omitted` and `note` account for it, and with a
  `workspace_root` the complete result is written to `full_result_file`. A
  result that needed no trimming carries none of those fields.

  The CLI is unaffected — `--json` still emits everything, which is what a
  pipeline wants.

## [0.1.0] - 2026-08-10

### Added

- `lookup <indicator>` — campaign context for an indicator from OTX community
  pulses: adversaries, malware families, ATT&CK techniques, targeted industries
  and countries, and tags, each with the number of pulses that named it, plus
  the reporting window and the pulses themselves newest first. The type is
  detected from the indicator's shape (IPv4, IPv6, domain, hostname, URL, MD5 /
  SHA1 / SHA256, CVE) and validated before any network I/O.
- Flags: `--sections`, `--limit`, `--anonymous`, `--json` / `-j`, `--refresh`,
  `--timeout`, `--input`, `-c` / `--config`. Bulk input from arguments, a file,
  or stdin; JSONL when there is more than one target.
- Only `general` is fetched by default — it is where `pulse_info` lives. The
  sections a sibling tool owns (`reputation`, `passive_dns`, `malware` /
  `analysis`, `url_list`) are opt-in through `--sections`.
- A name is looked up as both `domain` and `hostname` when the first finds
  nothing, and the result states which answered. OTX indexes a name's pulses
  under exactly one of the two but answers `200` either way, so without the
  second attempt a wrong guess is indistinguishable from a clean indicator.
- An empty result is reported as clean only when every lookup succeeded. If one
  failed, the result is marked `INCONCLUSIVE`, the failure is named, and the
  exit code is 1.
- Local request pacing against the published hourly ceiling (1,000 anonymous /
  10,000 with a key), since OTX returns no remaining-budget header.
- TTL result cache with atomic writes, scoped so keyed and anonymous answers
  never share an entry.
- `pulse <id>` — one pulse in full, with `--indicators` to list what it carries.
  This is the pivot from a single indicator to the rest of a campaign, and it
  works **without an API key**: the pulse detail response embeds the indicators.
  The detail reports no total, so the count is stated as unknown rather than
  guessed; with a key the paginated endpoint answers and the count is exact.
- `search <query>` — pulse search. Requires an API key, and says so precisely
  without spending a request when there is none.
- `cache status` and `cache clear`, with `--json`.
- `auth check` — the only way to find out whether the configured API key
  actually works. Indicator lookups answer anonymously, so a key with a typo in
  it still lets them succeed and still reports "authenticated", which means only
  that a key was sent; `/users/me` is the one endpoint that rejects a bad key.
  It answers with four distinct states — `valid`, `rejected`, `unreachable`,
  `absent` — because "we could not ask" is not "your key is bad", and exits 0
  only for `valid`. With no key configured it answers locally without spending a
  request.
- `mcp` — a dependency-free stdio JSON-RPC 2.0 MCP server exposing
  `lookup_indicator`, `get_pulse`, `search_pulses`, `cache_status` and
  `get_usage`, with an embedded manual that meta-tests pin to the code: every
  tool, every argument and every error code must appear in it. Tool failures
  are returned as results with `{code, message}` rather than as protocol
  errors, so the model sees them. Large pulse and indicator lists are written
  as JSON Lines under `workspace_root`, contained with `os.Root`.
- Shared flags (`--anonymous`, `--json`, `--refresh`, `--timeout`, `--config`)
  are declared once and mean the same thing in every command.

- Project scaffold: module `github.com/nlink-jp/otx-lookup`, `main.go` at the
  repository root, the `internal/` package skeleton (`indicator`, `otx`,
  `engine`, `cache`, `config`, `workspace`, `app`, `mcp`), the `e2e` package
  behind its build tag, the org Makefile with `build` → `dist/`, and the
  vendored signing and Homebrew tap-generation scripts.
- CLI dispatch for `lookup`, `pulse`, `search`, `cache` and `mcp`, plus
  `version` and `help`. `--version`, `-v` and the `version` subcommand print
  byte-identical output, pinned by a test — a Homebrew formula's `brew test`
  calls `--version` while the docs teach `version`.
- `config.example.toml` documenting the `[api]`, `[query]`, `[cache]`,
  `[network]`, `[ratelimit]` and `[mcp]` sections and their environment
  variables.
- Design record: [docs/ja/otx-lookup-rfp.ja.md](docs/ja/otx-lookup-rfp.ja.md)
  (primary) and [docs/en/otx-lookup-rfp.md](docs/en/otx-lookup-rfp.md).

### Fixed

- `internal/workspace` deferred its `Close` on both write paths, so a failure
  at close — a full disk surfaces there, not at write — would have returned the
  path to a truncated file while reporting how many records it held. Close is
  now checked. Found by errcheck.
- Pulse search failed to decode every response. `exact_match` is documented as
  a boolean and arrives as a string; declaring it `bool` made the whole search
  error out. It is now kept raw, and a test covers every type it could take.
- Pulse search returned the oldest reports first — a search for "qakbot" led
  with 2015. Newest-first is now requested explicitly.
- Long pulse tag lists are capped in text output. One measured pulse carried
  over 150 tags of scraped noise, which buried every other field.
- Flags placed after a target were silently ignored. Go's `flag` package stops
  parsing at the first positional argument, so `lookup paypal.com --limit 3`
  read the flag as two more targets and dropped the limit. Found by a live run,
  not by a test.

### Internal

- The upstream behaviour each package must account for is recorded in its
  `doc.go` and in AGENTS.md, measured against the live API rather than taken
  from the documentation — including the two endpoints that need an API key.
- The MCP server refuses a nil input stream instead of panicking.
- Live end-to-end suite behind the `e2e` build tag: 12 Go tests plus 27
  binary-level checks in `scripts/e2e.sh` covering exit codes, the stdout/stderr
  split, JSON and JSONL output, and a full MCP stdio session. Fixtures are
  chosen for stability and never assert an exact pulse count.
- `.golangci.yml` excluding only `fmt.Fprint*` to the CLI's own streams, so
  errcheck stays meaningful everywhere else. `make check` is green.
