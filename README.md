# otx-lookup

**Campaign context for an indicator, from OTX community pulses — as a CLI and a local MCP server.**

Every other lookup tool in this family answers "one indicator, one attribute": attribution ([asn-lookup](https://github.com/nlink-jp/asn-lookup)), registration ([whois-lookup](https://github.com/nlink-jp/whois-lookup)), reputation ([abuse-lookup](https://github.com/nlink-jp/abuse-lookup)), relationships ([rdns-lookup](https://github.com/nlink-jp/rdns-lookup)), current resolution ([doh-lookup](https://github.com/nlink-jp/doh-lookup)), what a hash is ([malware-lookup](https://github.com/nlink-jp/malware-lookup)), how a URL behaves ([urlscan-lookup](https://github.com/nlink-jp/urlscan-lookup)). None of them answers the question a triage actually turns on: **is this indicator part of a known campaign?**

otx-lookup reads the community reports — "pulses" — published on the [LevelBlue Open Threat Exchange](https://otx.alienvault.com/) and attaches what they claim about an indicator: **adversary, malware family, ATT&CK techniques, targeted industries and countries, who reported it and when**. From there you can pivot to the other indicators the same pulse carries, which is how one isolated alert becomes a campaign.

Because only a third-party index is read, **no packet reaches the target under investigation** — so like `rdns-lookup`, this belongs early in a triage. **The API key is optional**: every indicator section and the pulse detail answer anonymously.

> **This tool reports claims, not verdicts.** Pulses are community submissions of varying quality. The author, the vote counts, the false-positive flag and the validation records are shown alongside every result so you can weigh them. otx-lookup never decides that an indicator is malicious.

## Install

```bash
make build  # → dist/otx-lookup
```

## Usage

```bash
# Campaign context for an indicator — the type is detected from its shape
otx-lookup lookup 203.0.113.10
otx-lookup lookup evil.example.com
otx-lookup lookup 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
otx-lookup lookup CVE-2021-44228

# Sections that overlap the sibling tools are off by default; ask explicitly
otx-lookup lookup 203.0.113.10 --sections reputation,passive_dns

# Query without the configured API key, so the lookup is not recorded
# against your OTX account
otx-lookup lookup 203.0.113.10 --anonymous

# Read a pulse, then pivot to the indicators it carries — no API key needed
otx-lookup pulse 693096c1cabeccbc6b3a5def
otx-lookup pulse 693096c1cabeccbc6b3a5def --indicators

# Search pulses (needs an API key)
otx-lookup search "qakbot"

# Machine-readable; JSONL when there are multiple targets
otx-lookup lookup --json 203.0.113.10
otx-lookup lookup --json 203.0.113.10 evil.example.com

# Bulk input: arguments, a file, or stdin — paced against the rate limit
otx-lookup lookup --input targets.txt
cut -d, -f2 alerts.csv | otx-lookup lookup --json

# Cache
otx-lookup cache status
otx-lookup cache clear

# Is the configured key actually working?
otx-lookup auth check
```

### Which sections are off by default, and why

OTX carries sections that overlap four sibling tools. Showing them by default would leave you with two answers to the same question and no basis to prefer one, so they are opt-in via `--sections`:

| Section | Owned by | Why OTX's copy is a second opinion, not the answer |
|---|---|---|
| `reputation` | abuse-lookup | AbuseIPDB reports are attributable and scored |
| `passive_dns` | rdns-lookup | a 6-billion-record index built for exactly this question |
| `malware` / `analysis` | malware-lookup | three sources layered into one verdict |
| `url_list` | urlscan-lookup | a sandbox that actually loaded the URL |

What OTX alone provides — the pulse and everything hanging off it — is what you get by default.

### Why a domain is sometimes looked up twice

OTX has two types for names, `domain` and `hostname`, and it indexes a name's
pulses under exactly one of them — but **both endpoints answer `200` either
way**, so asking the wrong one reports zero pulses and looks exactly like a
clean indicator:

| Name | as `domain` | as `hostname` |
|---|---|---|
| `paypal.com` | 50 pulses | 0 |
| `bbc.co.uk` | 22 pulses | 0 |
| `www.bbc.co.uk` | 0 | 50 pulses |

The distinction is registrable-domain versus name-with-a-subdomain, which
counting labels cannot settle (`bbc.co.uk` has three labels and is a domain;
`mail.google.com` has three and is a hostname). So the shape only decides which
to ask first, and the other is asked when the first finds nothing. Which one
answered is printed with the result:

```
bbc.co.uk  [domain]  22 pulses held, 1 shown  CAPPED
  resolved: asked as hostname, then domain; domain answered
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Every target was looked up (zero pulses is a valid answer) |
| 1 | An upstream failure prevented some lookups (what succeeded is printed) |
| 2 | Error — invalid input, bad configuration |

**An empty result is only reported as clean when every lookup succeeded.** If
one of them failed, the result is marked `INCONCLUSIVE` and the exit code is 1 —
"nothing reported this indicator" and "we could not ask" are identical in the
data and opposite in meaning, so they are never printed the same way.

## MCP server

```bash
otx-lookup mcp
```

Tools: `lookup_indicator`, `get_pulse`, `search_pulses`, `cache_status`, `get_usage`. **Call `get_usage` first** — it returns the full reference, the result schema, and the error-recovery table. Tool errors are structured JSON (`{code, message}`); an indicator with no pulses is a normal result, not an error. Large results are written to `workspace_root` and only the path plus a count summary is returned, so an agent's context is not flooded.

Register it with Claude Code:

```json
{
  "mcpServers": {
    "otx-lookup": {
      "command": "otx-lookup",
      "args": ["mcp"]
    }
  }
}
```

## Configuration

**Precedence: flag > environment variable > config file > built-in default.** The config file is optional; see [config.example.toml](config.example.toml).

| Setting | TOML | Env | Default |
|---|---|---|---|
| API key | `[api] key` | `OTX_LOOKUP_API_KEY` / `OTX_API_KEY` | (none) |
| API root | `[api] base_url` | `OTX_LOOKUP_BASE_URL` | `https://otx.alienvault.com/api/v1` |
| Pulses shown | `[query] default_limit` | `OTX_LOOKUP_DEFAULT_LIMIT` | `10` |
| Cache TTL (hours) | `[cache] ttl_hours` | `OTX_LOOKUP_CACHE_TTL_HOURS` | `24` |
| Cache directory | `[cache] dir` | `OTX_LOOKUP_CACHE_DIR` | `~/.cache/otx-lookup` |
| Network timeout | `[network] timeout_seconds` | `OTX_LOOKUP_TIMEOUT_SECONDS` | `30` |
| Hourly request budget | `[ratelimit] max_per_hour` | `OTX_LOOKUP_MAX_PER_HOUR` | (from key presence) |
| MCP inline limit | `[mcp] inline_max_records` | `OTX_LOOKUP_MCP_INLINE_MAX` | `200` |
| MCP workspace | `[mcp] workspace` | `OTX_LOOKUP_WORKSPACE` | (none) |

`OTX_API_KEY` is accepted as well as `OTX_LOOKUP_API_KEY` because that is the variable the official OTX SDKs conventionally use — an environment already set up for them works here unchanged.

### What an API key does and does not buy

A free account at [otx.alienvault.com](https://otx.alienvault.com/) issues one key; OTX has no scope mechanism, so that key carries the account's full authority. Without it:

| | Anonymous | With a key |
|---|---|---|
| Indicator sections (all types) | yes | yes |
| Pulse detail, related pulses | yes | yes |
| The indicators a pulse carries | yes — the detail embeds them | yes, **plus the exact total** |
| Pulse search | no | yes |
| Rate ceiling | 1,000 req/h | 10,000 req/h |

**The pivot works without a key**, which is the part worth knowing: the pulse detail response embeds the pulse's indicators, so `pulse <id> --indicators` returns them anonymously. What the detail does *not* carry is a total — no count, no pagination cursor — so an embedded set that stopped early is indistinguishable from a complete one. `otx-lookup` says so rather than guessing:

```
indicators: 4 returned; the total is unknown — the pulse detail reports none,
            and the endpoint that does needs an API key
```

With a key the paginated endpoint answers instead, and the count becomes exact (`indicators: 4 of 4090`).

A query sent with a key is recorded against your OTX account. `--anonymous` skips the key deliberately for the lookups that do not need it.

**A key with a typo in it fails silently.** Indicator lookups answer anonymously, so they still succeed with a bad key — and still print `authenticated`, which only means a key was sent. `auth check` is the one command that asks upstream:

```
$ otx-lookup auth check
API key: valid  (account analyst, id 1234567)
  member since: 3344 days ago
  rate ceiling: 10000 requests/hour
  unlocks:      pulse search and the exact indicator total of a pulse
```

It distinguishes four states — `valid`, `rejected`, `unreachable` and `absent` — because "we could not ask" is not "your key is bad". Exit code 0 only for `valid`, so `otx-lookup auth check && ...` is safe to script on. With no key configured it answers locally and spends no request.

## Terms and attribution

**OTX is free for non-commercial use only** ([End User Agreement](https://www.levelblue.com/legal/otx-eula-terms)). Integrating OTX data into your own tooling is the intended use of the DirectConnect API, but the non-commercial restriction is yours to honour.

This tool speaks to the API directly and takes no SDK as a dependency. The official [OTX-Go-SDK](https://github.com/AlienVault-OTX/OTX-Go-SDK) (Apache-2.0) served as a reference for the request shape; it implements only `users/me`, `subscriptions` and `pulses/{id}`, and its last commit predates Go modules.

## License

MIT — see [LICENSE](LICENSE).
