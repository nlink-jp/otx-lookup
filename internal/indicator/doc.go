// Package indicator classifies a user-supplied string into the indicator type
// OTX addresses it by — IPv4, IPv6, domain, hostname, URL, file hash (MD5 32 /
// SHA1 40 / SHA256 64 hex chars), or CVE — and normalizes it into the path
// segment the API expects.
//
// This is a validation gate, not a convenience: classification runs before any
// network I/O, so a malformed target never reaches OTX. Taking a single
// indicator argument and deciding its type here (rather than making the user
// pick a subcommand per type, as rdns-lookup must) is possible because the
// shapes are mutually unambiguous — a 64-char hex string is not a domain, and
// a CVE identifier is not a URL.
package indicator
