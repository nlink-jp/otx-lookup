// Package workspace writes large MCP results to files under a caller-supplied
// directory, contained with os.Root so a crafted name cannot escape it.
//
// An agent's context is scarcer than disk. A pulse indicator list runs to
// thousands of entries, so above the inline threshold the MCP tools return a
// path plus a count summary instead of the records themselves.
package workspace
