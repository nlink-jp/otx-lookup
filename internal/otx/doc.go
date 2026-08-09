// Package otx is the client for the LevelBlue Open Threat Exchange
// DirectConnect API (https://otx.alienvault.com/api/v1): the indicator
// sections, the pulse detail, the pulse related list, the pulse indicator
// list, and pulse search.
//
// The official OTX-Go-SDK is deliberately not a dependency. Its last push was
// 2021-10-28, it predates modules (no go.mod, GOPATH-era src/otxapi layout),
// and it implements only users/me, subscriptions and pulses/{id} — the
// indicator endpoints this tool is built on are absent. It is Apache-2.0
// licensed and served as a reference for the request shape; see the
// attribution in README.md.
//
// Two upstream facts shape this package:
//
//   - Authentication is optional and partial. Every indicator section, the
//     pulse detail and the pulse related list answer anonymously; only the
//     pulse indicator list, pulse search and the subscription feed require the
//     X-OTX-API-KEY header. The client therefore reports which requests need a
//     key rather than refusing to start without one.
//
//   - No rate budget comes back. Responses carry no remaining-quota header
//     (the only OTX-specific header observed is X-OTX-ACTIVE), so unlike
//     rdns-lookup — which paces on the budget upstream reports — pacing here
//     has to be counted client-side against the published ceiling of 1,000
//     req/h anonymous and 10,000 req/h with a key.
package otx
