// Package cache is a fixed-TTL JSON-file cache with atomic writes, shared by
// the CLI and the MCP server.
//
// The TTL is applied at read time rather than at write time, so changing
// ttl_hours in the config takes effect on entries already on disk.
//
// Degraded results are never cached. A lookup that fell back because an
// upstream call failed would otherwise freeze an incomplete answer in place
// for the whole TTL, and the analyst would have no way to tell.
package cache
