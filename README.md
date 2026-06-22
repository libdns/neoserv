Neoserv for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/neoserv)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Neoserv](https://moj.neoserv.si), allowing you to manage DNS records.

## Installation

```bash
go get github.com/libdns/neoserv
```

## Usage

You can check out a minimal example of using this provider in the [examples](./examples) directory.

Run it with:

```bash
NEOSERV_USERNAME=your@email.com NEOSERV_PASSWORD=your_password NEOSERV_ZONE=your.domain go run ./examples/neoserv.go
```

## Implemented Interfaces

The provider implements the following `libdns` interfaces:

- `libdns.ZoneLister` — list the zones available to the account
- `libdns.RecordGetter` — list records in a zone
- `libdns.RecordAppender` — add records to a zone
- `libdns.RecordSetter` — create or update records
- `libdns.RecordDeleter` — delete records

## Supported Record Types

All record types Neoserv supports are handled, including their type-specific fields:

| Type   | Go type          | Extra fields           |
| ------ | ---------------- | ---------------------- |
| A/AAAA | `libdns.Address` | —                      |
| CNAME  | `libdns.CNAME`   | —                      |
| NS     | `libdns.NS`      | —                      |
| TXT    | `libdns.TXT`     | —                      |
| MX     | `libdns.MX`      | preference             |
| SRV    | `libdns.SRV`     | priority, weight, port |
| CAA    | `libdns.CAA`     | flags, tag             |
| ALIAS  | `neoserv.ALIAS`  | —                      |

`ALIAS` has no `libdns` equivalent, so this package provides its own `neoserv.ALIAS`
type — an apex-capable, CNAME-like record. It satisfies `libdns.Record` and works
with all of the provider's record methods just like the built-in types.

## Behavior

The provider follows the [libdns interface semantics](https://pkg.go.dev/github.com/libdns/libdns):

- **AppendRecords** only creates records and never modifies existing ones. Because
  Neoserv's API does not return the ID of a created record, new records are
  identified by diffing the zone before and after the call. Any `ProviderData` on
  the input is ignored.
- **SetRecords** replaces RRsets: for each `(name, type)` pair in the input, the
  only records of that pair left in the zone are the ones provided. Matching
  records are kept, others are updated in place (preserving their ID) or created,
  and surplus records of that pair are deleted. Records of other `(name, type)`
  pairs are untouched. It is not atomic.
- **DeleteRecords** matches by content — the name must match, while type, TTL, and
  value are matched only when non-empty (so they act as wildcards when omitted).
  A `ProviderData` ID, when present, targets exactly that record. Records that do
  not exist are silently ignored.

All record methods are safe for concurrent use (serialized per zone), and transient
network errors and `429`/`5xx` responses are retried with backoff. Record types
that Neoserv exposes but libdns does not model (e.g. `WR` redirects) are returned as
an internal record type that still round-trips through delete.

## Session Caching

Neoserv rate-limits the login endpoint, which is easy to hit while developing or
running the test suite. To avoid this, the provider reuses an existing session
instead of logging in on every run. On a successful login the `moj_session` cookie
is persisted to disk and reused (after a cheap validity check) until it expires;
only when no valid cached session exists does the provider log in again.

By default the cache lives in a per-account file in the OS temp directory. You can
point it elsewhere, or opt out of disk caching entirely:

```go
provider := neoserv.Provider{
	Username:            "your-neoserv-email",
	Password:            "your-neoserv-password",
	SessionCachePath:    "/path/to/session.json", // optional; default is a temp file
	DisableSessionCache: true,                     // opt out of on-disk caching
}
```

If too many logins are attempted, Neoserv temporarily blocks logging in for the
account (about an hour). When a method needs to log in during that window it
returns `neoserv.ErrLoginRateLimited`, which callers can detect and back off from:

```go
if errors.Is(err, neoserv.ErrLoginRateLimited) {
	// blocked from logging in; retry later
}
```

A still-valid cached session keeps working during the block, since it does not
require logging in.

## Supported TTL Values

Neoserv only supports specific TTL values. Check the `provider.go` file for the list of supported TTL values.

By default, if an unsupported TTL is provided, the provider will use the closest supported value that is greater than or equal to the provided value. If you want to treat unsupported TTL values as errors, set `UnsupportedTTLisError` to `true` when creating the provider:

```go
provider := neoserv.Provider{
	Username:              "your-neoserv-email",
	Password:              "your-neoserv-password",
	UnsupportedTTLisError: true,
}
```

### RFC 2136 proxy

The [`examples/rfc2136`](./examples/rfc2136) directory contains a small DNS server
that accepts TSIG-authenticated [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
`UPDATE` messages and applies them to Neoserv through this provider. It lets
off-the-shelf tooling that speaks RFC 2136 — `certbot --dns-rfc2136`,
cert-manager, `acme.sh`, `nsupdate`, external-dns — manage Neoserv records
without writing any Go. It is an example/demo, not a hardened server
(prerequisites are not enforced and updates are not atomic).

It is its own Go module (so `miekg/dns` does not become a dependency of the
provider), configured via environment variables:

| Variable              | Default            | Description                                |
| --------------------- | ------------------ | ------------------------------------------ |
| `NEOSERV_USERNAME`    | —                  | Neoserv account email (required)           |
| `NEOSERV_PASSWORD`    | —                  | Neoserv account password (required)        |
| `NEOSERV_ZONE`        | —                  | optional; if set, only this zone is accepted |
| `RFC2136_TSIG_SECRET` | —                  | base64-encoded TSIG shared secret (required) |
| `RFC2136_TSIG_KEY`    | `acme.`            | TSIG key name                              |
| `RFC2136_TSIG_ALG`    | `hmac-sha256.`     | TSIG algorithm                             |
| `RFC2136_LISTEN`      | `0.0.0.0:5353`     | listen address (served on UDP and TCP)     |

Run it:

```bash
cd examples/rfc2136
RFC2136_TSIG_SECRET=$(head -c32 /dev/urandom | base64) \
NEOSERV_USERNAME=your@email.com NEOSERV_PASSWORD=your_password \
go run .
```

Then drive it with any RFC 2136 client, for example `nsupdate`:

```
server 127.0.0.1 5353
key hmac-sha256:acme. <same-base64-secret>
zone your.domain.
update add _acme-challenge.your.domain. 60 TXT "token"
send
```