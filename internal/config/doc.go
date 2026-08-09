// Package config resolves settings from, in decreasing precedence: command
// line flags, environment variables, the config file, and built-in defaults.
//
// The file is the sectioned-TOML subset used across the series
// ([api], [query], [cache], [network], [ratelimit], [mcp]), read from
// $XDG_CONFIG_HOME/otx-lookup/config.toml and ~/.config/otx-lookup/config.toml.
//
// The API key is a secret: it is read from OTX_LOOKUP_API_KEY or OTX_API_KEY
// (the variable the official OTX SDKs conventionally use, accepted so an
// existing environment works unchanged), or from [api] key. It is sent only in
// the X-OTX-API-KEY header — never in a URL, never logged.
package config
