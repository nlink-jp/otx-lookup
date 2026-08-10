# otx-lookup MCP server

Campaign context for an indicator of compromise, from the community reports
("pulses") of the LevelBlue Open Threat Exchange.

## What this server is for, and what it is not

Every other lookup server in this fleet answers "one indicator, one attribute":
attribution, registration, reputation, DNS relationships, what a hash is, how a
URL behaves. This one answers a different question — **is this indicator part of
a known campaign?** — and returns the adversary, malware family, ATT&CK
techniques, targeted industries and countries it was reported under, by whom,
and when.

Two consequences for how you should use it:

- **It reports claims, not verdicts, and the claims are of wildly uneven
  quality.** Anyone can submit a pulse, and a curated incident write-up arrives
  in exactly the same shape as an automated blocklist of 300,000 indicators.
  Every field holds whatever its author typed. Actually observed in one lookup:

  | Field | What was in it |
  |---|---|
  | `adversary` | a pasted paragraph of analysis, not an actor name |
  | `tags` | an MD5 hash; elsewhere `"Imphash: … \| Imports (additional)"` |
  | `references` | an empty string; elsewhere prose instead of a URL |
  | `industries` | `"Legal, Financial, Healthcare, Government, …"` as one value |

  So: read the `pulses` count on each aggregate value as its corroboration —
  what five independent reports agree on is worth far more than what one says.
  Check `indicator_count` on a pulse to tell an analysis from a feed dump.
  Weigh the author, the vote counts, the upstream `validation` notes and
  `false_positive_reports`, all of which come back with every result. This
  server never decides that an indicator is malicious. Neither should you, on
  this evidence alone.
- **It duplicates no sibling.** `reputation`, `passive_dns`, `malware` /
  `analysis` and `url_list` are omitted by default because `abuse-lookup`,
  `rdns-lookup`, `malware-lookup` and `urlscan-lookup` each answer one of them
  better. Ask for them through `sections` only when you deliberately want OTX's
  second opinion.

Only a third-party index is read, so **no packet reaches the target under
investigation**. This is safe as an opening move in a triage.

## Tools

### `lookup_indicator`

Campaign context for one indicator.

| Argument | Type | Meaning |
|---|---|---|
| `indicator` | string, required | IPv4, IPv6, domain, hostname, URL, MD5/SHA1/SHA256, or CVE. The type is detected from its shape. |
| `sections` | string[] | Extra sections beyond the default. |
| `limit` | integer | Pulses to list. |
| `anonymous` | boolean | Query without the configured API key. |
| `refresh` | boolean | Bypass the result cache. |
| `workspace_root` | string | Directory for file-mediated results. |

Key fields in the result:

- `pulses_held` vs `pulses_shown` — **always read both.** `pulses_held` is a
  lower bound: OTX returns exactly 50 for heavily-reported indicators, which is
  a page size rather than a total. `capped: true` marks a partial list.
- `context` — the aggregate across every pulse: `adversaries`,
  `malware_families`, `attack_ids`, `industries`, `targeted_countries`, `tags`,
  each as `{value, pulses}`. The count is how many independent reports named it,
  which is the difference between a campaign the community agrees on and one
  analyst's guess.
- `type` and `tried_types` — which OTX indicator type answered. A name is asked
  as `domain` and then `hostname` (or the reverse) because OTX indexes a name
  under exactly one of them and answers 200 either way.
- `incomplete` — **the field that decides whether an empty result means
  anything.** When it is true, one of the lookups failed, so `pulses_held: 0`
  means "we could not ask", not "nothing reported this". Never report an
  indicator as clean on an `incomplete` result.
- `validation` and `false_positive_reports` — upstream's own doubt about the
  indicator. A whitelisted domain will still carry pulses.
- `degraded` — what could not be fetched.

### `get_pulse`

One pulse in full, and the indicators it carries. This is the pivot from a
single indicator to the rest of a campaign: take a `pulse_id` from
`lookup_indicator`, call this with `indicators: true`, and you have the other
indicators reported alongside it.

| Argument | Type | Meaning |
|---|---|---|
| `pulse_id` | string, required | From `lookup_indicator`. |
| `indicators` | boolean | Include the indicators the pulse carries. |
| `limit` | integer | Maximum indicators to return. |
| `anonymous` | boolean | Query without the configured API key. |
| `refresh` | boolean | Bypass the result cache. |
| `workspace_root` | string | Directory for file-mediated results. |

`indicators_exact` tells you whether `indicators_held` can be trusted. Without
an API key the pulse detail embeds indicators but reports no total, so
`indicators_held` is `-1` and `indicators_exact` is `false` — the set you got
may be a page. With a key the paginated endpoint answers and both become exact.

Pivoting is deliberately two steps rather than one "give me everything related"
call: pulses vary in quality, and which of them to trust is your judgement, not
something to average away.

### `search_pulses`

Free-text search over pulses. **Requires an API key.** Without one this returns
`auth_required` and spends no request.

| Argument | Type | Meaning |
|---|---|---|
| `query` | string, required | Free text. |
| `limit` | integer | Results per page. |
| `page` | integer | Page number, from 1. |
| `anonymous` | boolean | Query without the key (this tool will then fail). |

Search results are never cached: a search asks what exists right now.

### `cache_status`

Where the cache lives, how many entries it holds, its TTL, and whether a key is
configured. No arguments.

### `get_usage`

This document. No arguments.

## The API key

The key is optional, and most of this server works without one.

| | Anonymous | With a key |
|---|---|---|
| `lookup_indicator` | yes | yes |
| `get_pulse` (with indicators) | yes | yes, plus an exact total |
| `search_pulses` | no | yes |
| Hourly request budget | 1,000 | 10,000 |

A query sent with a key is recorded against the operator's OTX account. Pass
`anonymous: true` on a call that should not be.

## Errors

Tool errors come back as `{"code": ..., "message": ...}` with `isError: true`.

| Code | Meaning | What to do |
|---|---|---|
| `invalid_argument` | The arguments were wrong — a missing `indicator`, an unknown field, an unparseable target. | Fix the call. The message names the problem. |
| `bad_request` | Upstream rejected the indicator itself as malformed. | Check the indicator. Do not retry unchanged. |
| `auth_required` | The endpoint needs an API key. | Use `lookup_indicator` / `get_pulse`, which do not, or tell the operator to configure `OTX_LOOKUP_API_KEY`. |
| `not_found` | No such pulse or hash in OTX. | For a hash this is a real answer: OTX has never seen it. |
| `rate_limited` | The hourly budget is exhausted. | Wait. Do not retry in a loop; the budget refills over an hour. |
| `upstream_error` | OTX returned 5xx or an unexpected status. | Retry once after a pause. OTX does return 500s and 504s under load. |
| `network_error` | The request never completed. | Check connectivity, then retry once. |
| `decode_error` | The response was not the JSON expected. | Report it; this usually means upstream changed shape. |

**An indicator with no pulses is not an error.** Most indicators an analyst
types have never been reported by anyone. That is a successful result — as long
as `incomplete` is false.

## What gets trimmed, and how you know

`limit` caps the pulse list. It does **not** bound the aggregate or the
references, which are independent of it — a lookup of a heavily-analysed CVE
can otherwise return well over 100 KB, most of it scraped tags from feed-dump
pulses. So `lookup_indicator` keeps the top 25 of each `context` category and
the first 25 references.

The categories are ranked by how many pulses named each value, so what is
dropped is always the least-corroborated tail. Nothing is dropped silently:

- `context_omitted` — a per-category count of what was left out, absent when
  nothing was.
- `references_omitted` — the same for references.
- `full_result_file` — with a `workspace_root`, the complete untrimmed result
  as JSON. Read it when the tail matters.
- `note` — plain-language summary of all of the above.

An untrimmed result carries none of these fields, so their presence is itself
the signal that you are looking at a partial view.

## File-mediated results

When a pulse list or indicator list exceeds the configured inline limit
(default 200) and a `workspace_root` is given, the records are written there as
JSON Lines and the result carries the path, the total, and the first records
inline. Read the file when you need the rest; do not ask for it to be inlined.
