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

