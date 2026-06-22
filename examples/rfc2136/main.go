// Command rfc2136 is a small RFC 2136 (DNS UPDATE) proxy that translates
// TSIG-authenticated UPDATE messages into calls on the Neoserv libdns provider.
//
// It lets standard tooling that speaks RFC 2136 — certbot --dns-rfc2136,
// cert-manager, acme.sh, nsupdate, external-dns — manage Neoserv DNS records
// without writing Go against the provider API.
//
// This is an example/demo, not a hardened production server: prerequisites are
// not enforced and updates are not applied atomically.
//
// Configuration (environment variables):
//
//	NEOSERV_USERNAME     Neoserv account email (required)
//	NEOSERV_PASSWORD     Neoserv account password (required)
//	NEOSERV_ZONE         optional: if set, only this zone is accepted
//	RFC2136_TSIG_SECRET  base64-encoded TSIG shared secret (required)
//	RFC2136_TSIG_KEY     TSIG key name, default "acme."
//	RFC2136_TSIG_ALG     TSIG algorithm, default "hmac-sha256."
//	RFC2136_LISTEN       listen address, default "0.0.0.0:5353"
package main

import (
	"context"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/neoserv"
	"github.com/miekg/dns"
)

// proxy holds the configured provider and the settings the DNS handler needs.
type proxy struct {
	provider    *neoserv.Provider
	tsigKeyName string
	tsigAlg     string
	// allowZone, when non-empty, is the only zone (FQDN, lower-case) the proxy
	// will accept updates for. Empty means accept any zone the account owns.
	allowZone string
}

func main() {
	username := os.Getenv("NEOSERV_USERNAME")
	password := os.Getenv("NEOSERV_PASSWORD")
	keyName := os.Getenv("RFC2136_TSIG_KEY")
	if keyName == "" {
		keyName = "acme."
	}
	keyName = dns.Fqdn(keyName)
	secret := os.Getenv("RFC2136_TSIG_SECRET")
	if username == "" || password == "" || secret == "" {
		log.Fatal("set NEOSERV_USERNAME, NEOSERV_PASSWORD and RFC2136_TSIG_SECRET")
	}

	alg := os.Getenv("RFC2136_TSIG_ALG")
	if alg == "" {
		alg = "hmac-sha256."
	}
	listen := os.Getenv("RFC2136_LISTEN")
	if listen == "" {
		listen = "0.0.0.0:5353"
	}

	p := &proxy{
		provider:    &neoserv.Provider{Username: username, Password: password},
		tsigKeyName: keyName,
		tsigAlg:     dns.Fqdn(alg),
		allowZone:   strings.ToLower(dns.Fqdn(os.Getenv("NEOSERV_ZONE"))),
	}
	if p.allowZone == "." {
		p.allowZone = ""
	}

	dns.HandleFunc(".", p.handleUpdate)
	tsig := map[string]string{keyName: secret}

	servers := []*dns.Server{
		{Addr: listen, Net: "udp", TsigSecret: tsig, MsgAcceptFunc: acceptUpdate},
		{Addr: listen, Net: "tcp", TsigSecret: tsig, MsgAcceptFunc: acceptUpdate},
	}
	for _, s := range servers {
		go func() {
			if err := s.ListenAndServe(); err != nil {
				log.Fatalf("listen %s/%s: %v", s.Addr, s.Net, err)
			}
		}()
	}
	log.Printf("RFC 2136 proxy listening on %s (udp+tcp), TSIG key %q", listen, keyName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	for _, s := range servers {
		_ = s.Shutdown()
	}
}

// acceptUpdate permits OpcodeUpdate messages, which the default miekg/dns accept
// function rejects with NOTIMP before the handler ever runs. Queries and notifies
// are still accepted so the handler can reply to them itself.
func acceptUpdate(dh dns.Header) dns.MsgAcceptAction {
	const qrBit = 1 << 15 // response bit; we only serve requests
	if dh.Bits&qrBit != 0 {
		return dns.MsgIgnore
	}
	switch int(dh.Bits>>11) & 0xF {
	case dns.OpcodeQuery, dns.OpcodeNotify, dns.OpcodeUpdate:
		return dns.MsgAccept
	default:
		return dns.MsgRejectNotImplemented
	}
}

func (p *proxy) handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	reply := func(rcode int) {
		m.SetRcode(r, rcode)
		// Sign the reply with the same key so the client accepts it. Only
		// possible when the request itself carried a (valid) TSIG.
		if r.IsTsig() != nil && w.TsigStatus() == nil {
			m.SetTsig(p.tsigKeyName, p.tsigAlg, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(m)
	}

	if r.Opcode != dns.OpcodeUpdate {
		log.Printf("non-update opcode %d from %s — refusing", r.Opcode, w.RemoteAddr())
		reply(dns.RcodeRefused)
		return
	}

	// Require a valid TSIG on every update.
	if tsig := r.IsTsig(); tsig == nil || w.TsigStatus() != nil {
		keyAttempted := ""
		if tsig != nil {
			keyAttempted = tsig.Hdr.Name
		}
		log.Printf("rejected update from %s: missing or invalid TSIG (key=%q status: %v)", w.RemoteAddr(), keyAttempted, w.TsigStatus())
		reply(dns.RcodeNotAuth)
		return
	}

	if len(r.Question) != 1 || r.Question[0].Qtype != dns.TypeSOA {
		reply(dns.RcodeFormatError)
		return
	}
	zone := r.Question[0].Name
	if p.allowZone != "" && !strings.EqualFold(zone, p.allowZone) {
		log.Printf("rejected update from %s: zone %q not in allowlist", w.RemoteAddr(), zone)
		reply(dns.RcodeNotZone)
		return
	}

	log.Printf("update from %s: zone=%q key=%q records=%d", w.RemoteAddr(), zone, r.IsTsig().Hdr.Name, len(r.Ns))

	// Prerequisites (r.Answer) are not enforced by this example.

	var adds, deletes []libdns.Record
	for _, rr := range r.Ns {
		hdr := rr.Header()
		name := libdns.RelativeName(hdr.Name, zone)
		switch hdr.Class {
		case dns.ClassNONE:
			// Delete an individual RR from an RRset (rdata is significant).
			log.Printf("  - %s %s (exact RR)", hdr.Name, dns.TypeToString[hdr.Rrtype])
			deletes = append(deletes, toRecord(rr, name, 0))
		case dns.ClassANY:
			if hdr.Rrtype == dns.TypeANY {
				// Delete all RRsets at the name.
				log.Printf("  - %s ANY (all records at name)", hdr.Name)
				deletes = append(deletes, libdns.RR{Name: name})
			} else {
				// Delete an entire RRset (a type at a name).
				log.Printf("  - %s %s (entire RRset)", hdr.Name, dns.TypeToString[hdr.Rrtype])
				deletes = append(deletes, libdns.RR{
					Type: dns.TypeToString[hdr.Rrtype],
					Name: name,
				})
			}
		default:
			// Add to an RRset.
			log.Printf("  + %s %s TTL=%ds", hdr.Name, dns.TypeToString[hdr.Rrtype], hdr.Ttl)
			adds = append(adds, toRecord(rr, name, time.Duration(hdr.Ttl)*time.Second))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Process deletes before adds. The provider serializes per-zone
	// read-modify-write internally, so concurrent updates are safe.
	if len(deletes) > 0 {
		log.Printf("deleting %d record(s) in %q", len(deletes), zone)
		if _, err := p.provider.DeleteRecords(ctx, zone, deletes); err != nil {
			log.Printf("DeleteRecords for %q failed: %v", zone, err)
			reply(dns.RcodeServerFailure)
			return
		}
		log.Printf("deleted %d record(s) in %q", len(deletes), zone)
	}
	if len(adds) > 0 {
		log.Printf("adding %d record(s) to %q", len(adds), zone)
		if _, err := p.provider.AppendRecords(ctx, zone, adds); err != nil {
			log.Printf("AppendRecords for %q failed: %v", zone, err)
			reply(dns.RcodeServerFailure)
			return
		}
		log.Printf("added %d record(s) to %q", len(adds), zone)
	}

	log.Printf("update for %q ok: %d add(s), %d delete(s)", zone, len(adds), len(deletes))
	reply(dns.RcodeSuccess)
}

// toRecord converts a miekg RR to a libdns.Record with the given relative name
// and TTL. For types where the provider uses a typed libdns record (TXT in
// particular) the appropriate concrete type is returned so that the string
// representation matches what the provider stores and reads back. All other
// types fall back to a generic libdns.RR using the RDATA string. Unsupported
// types surface later as a provider error.
func toRecord(rr dns.RR, name string, ttl time.Duration) libdns.Record {
	switch v := rr.(type) {
	case *dns.A:
		ip, _ := netip.AddrFromSlice(v.A)
		return libdns.Address{Name: name, TTL: ttl, IP: ip.Unmap()}
	case *dns.AAAA:
		ip, _ := netip.AddrFromSlice(v.AAAA)
		return libdns.Address{Name: name, TTL: ttl, IP: ip.Unmap()}
	case *dns.CNAME:
		return libdns.CNAME{Name: name, TTL: ttl, Target: strings.TrimSuffix(v.Target, ".")}
	case *dns.NS:
		return libdns.NS{Name: name, TTL: ttl, Target: strings.TrimSuffix(v.Ns, ".")}
	case *dns.MX:
		return libdns.MX{Name: name, TTL: ttl, Preference: v.Preference, Target: strings.TrimSuffix(v.Mx, ".")}
	case *dns.SRV:
		// Service and Transport are left empty so libdns.SRV.RR() uses Name
		// verbatim — the underscored labels are already part of the owner name.
		return libdns.SRV{Name: name, TTL: ttl, Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: strings.TrimSuffix(v.Target, ".")}
	case *dns.TXT:
		return libdns.TXT{Name: name, TTL: ttl, Text: strings.Join(v.Txt, "")}
	case *dns.CAA:
		return libdns.CAA{Name: name, TTL: ttl, Flags: v.Flag, Tag: v.Tag, Value: v.Value}
	default:
		hdr := rr.Header()
		raw := strings.TrimSpace(strings.TrimPrefix(rr.String(), hdr.String()))
		return libdns.RR{Type: dns.TypeToString[hdr.Rrtype], Name: name, TTL: ttl, Data: raw}
	}
}
