// Package mcp is a dependency-free stdio JSON-RPC 2.0 MCP server exposing
// lookup_indicator, get_pulse, search_pulses, cache_status and get_usage.
//
// get_usage is canonical: the mcp-tactics skill deliberately documents no
// parameters, so the embedded manual is what an agent reads before its first
// call. Tool errors are structured JSON ({code, message}).
//
// MCP has no protocol-level cancel; a closing stdin is the shutdown signal.
package mcp
