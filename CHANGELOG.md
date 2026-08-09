# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

### Internal

- The subcommands are dispatched but not yet implemented; they exit 2 saying
  so. `internal/` holds package documentation and no logic — the observed
  upstream behaviour each package must account for is recorded in its
  `doc.go` so the constraint is present where the code will be written.

## [0.1.0]

Not yet assigned. Phase 1 of the development plan (indicator classification,
the OTX client, the engine, and the `lookup` command) is the content of this
release; see the RFP for the full plan.
