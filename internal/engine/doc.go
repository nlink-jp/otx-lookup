// Package engine is the shared core behind both the CLI and the MCP server:
// classify the indicator, consult the cache, call otx, and aggregate the
// response into the campaign context that is this tool's reason to exist —
// adversaries, malware families, ATT&CK technique IDs, targeted industries and
// countries, tags, and the references that lead to primary sources.
//
// Sharing the engine is what keeps the two faces from drifting: an agent
// calling the MCP server and a human typing the CLI must get the same answer
// for the same indicator.
//
// Two rules live here rather than in the presentation layer:
//
//   - A partial answer is never presented as a complete one. pulse_info.count
//     can reflect a page rather than a true total (example.com returns 50), so
//     what upstream holds is always reported next to what was retrieved —
//     the honesty principle inherited from rdns-lookup.
//
//   - No verdict is invented. Pulses are community submissions of varying
//     quality; the engine surfaces the author, vote counts, false-positive
//     flag and validation records as evidence, and leaves "malicious or not"
//     to the analyst or the calling agent.
package engine
