package neoserv

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
)

var (
	username = ""
	password = ""
	zone     = ""
)

var (
	provider Provider
	ctx      = context.Background()
)

func init() {
	err := godotenv.Load(".test.env")
	if err != nil {
		panic(err)
	}
	username = os.Getenv("NEOSERV_USERNAME")
	password = os.Getenv("NEOSERV_PASSWORD")
	zone = os.Getenv("NEOSERV_ZONE")

	if username == "" || password == "" || zone == "" {
		panic("missing required environment variables NEOSERV_USERNAME, NEOSERV_PASSWORD, or NEOSERV_ZONE")
	}
	provider = Provider{
		Username: username,
		Password: password,
	}
	err = provider.init()
	if err != nil {
		panic(err)
	}
}

func TestAuthenticateCorrect(t *testing.T) {
	err := provider.authenticate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cookies := provider.client.Jar.Cookies(urlBaseP)
	if len(cookies) == 0 {
		t.Fatal("no cookies set")
	}
	var session *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "moj_session" {
			session = cookie
			break
		}
	}

	if session == nil {
		t.Fatal("moj_session cookie not set")
	}

	t.Logf("Authenticated as %s", username)
	t.Logf("moj_session cookie: %s", session)
}

func TestAuthenticateIncorrect(t *testing.T) {
	// Use a dedicated provider so the shared one keeps its valid session and
	// correct credentials for the remaining tests. DisableSessionCache forces
	// the login path; otherwise the cached valid session (keyed by the shared
	// username) would be reused and the wrong password never exercised.
	bad := Provider{Username: username, Password: "incorrect", DisableSessionCache: true}
	if err := bad.init(); err != nil {
		t.Fatal(err)
	}
	err := bad.authenticate(ctx)
	if err == nil {
		t.Fatal("authentication succeeded with incorrect password")
	}
	if errors.Is(err, ErrLoginRateLimited) {
		t.Skipf("login rate limited; cannot exercise the incorrect-password path: %s", err)
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed', got %s", err)
	}

	t.Logf("Authentication failed as expected: %s", err)
}

// TestSessionExpiryRecovery simulates an expired session by replacing the
// session cookie with a bogus value (which still passes the in-memory
// isAuthenticated check), then confirms that a normal data request transparently
// re-authenticates and succeeds instead of looping or failing.
//
// It uses a dedicated provider so corrupting the session cannot disturb the
// shared provider used by the other tests. The dedicated provider authenticates
// from the shared on-disk cache, so it does not require a login of its own.
func TestSessionExpiryRecovery(t *testing.T) {
	p := Provider{Username: username, Password: password}
	if err := p.init(); err != nil {
		t.Fatal(err)
	}
	if err := p.authenticate(ctx); err != nil {
		if errors.Is(err, ErrLoginRateLimited) {
			t.Skipf("login rate limited; cannot set up session recovery test: %s", err)
		}
		t.Fatal(err)
	}
	// Warm the zone-ID cache so the expiry is exercised on the records-page fetch.
	if _, err := p.GetRecords(ctx, zone); err != nil {
		t.Fatal(err)
	}
	p.setSessionCookie("bogus-expired-session-value")

	records, err := p.GetRecords(ctx, zone)
	if errors.Is(err, ErrLoginRateLimited) {
		t.Skipf("login rate limited; cannot exercise session recovery: %s", err)
	}
	if err != nil {
		t.Fatalf("expected transparent recovery, got error: %s", err)
	}
	if len(records) == 0 {
		t.Fatal("no records returned after recovery")
	}
	if !p.sessionValid(ctx) {
		t.Fatal("session not valid after recovery")
	}

	p.setSessionCookie("bogus-expired-session-value")

	appended, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-session-recovery", IP: netip.MustParseAddr("203.0.113.10"), TTL: TTL1h},
	})
	if errors.Is(err, ErrLoginRateLimited) {
		t.Skipf("login rate limited; cannot exercise session recovery: %s", err)
	}
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(appended) != 1 {
		t.Fatalf("expected 1 record added, got %d", len(appended))
	}
	if !p.sessionValid(ctx) {
		t.Fatal("session not valid after recovery")
	}

	_, err = p.DeleteRecords(ctx, zone, appended)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestGetZoneID(t *testing.T) {
	zoneID, err := provider.getZoneID(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Zone ID for %s: %s", zone, zoneID)
}

func TestGetZoneIDNotFound(t *testing.T) {
	_, err := provider.getZoneID(ctx, "nonexistent")
	if err == nil {
		t.Fatal("getZoneID succeeded with nonexistent zone")
	}
	if !strings.Contains(err.Error(), "zone nonexistent not found") {
		t.Fatalf("expected 'zone nonexistent not found', got %s", err)
	}

	t.Logf("getZoneID failed as expected: %s", err)
}

func TestListZones(t *testing.T) {
	zones, err := provider.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) == 0 {
		t.Fatal("no zones found")
	}

	want := strings.TrimSuffix(zone, ".")
	found := false
	for _, z := range zones {
		t.Logf("Zone: %s", z.Name)
		if strings.TrimSuffix(z.Name, ".") == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected zone %s in list", zone)
	}
}

func TestGetRecords(t *testing.T) {
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	if len(records) == 0 {
		t.Fatal("no records found")
	}

	for _, record := range records {
		t.Logf("Record: %v", record)
	}
}

func TestGetRecordsNotFound(t *testing.T) {
	_, err := provider.GetRecords(ctx, "nonexistent.com")
	if err == nil {
		t.Fatal("GetRecords succeeded with nonexistent zone")
	}

	t.Logf("GetRecords failed as expected: %s", err)
}

// TestRecordTypeRoundTrip exercises every libdns record type that Neoserv
// supports (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA) through a full
// append -> read back -> delete cycle. Each subtest cleans up after itself.
// All records use names under test*.zone.com.
func TestRecordTypeRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		record libdns.Record
	}{
		{"A", libdns.Address{Name: "test-a", IP: netip.MustParseAddr("203.0.113.10"), TTL: TTL1h}},
		{"AAAA", libdns.Address{Name: "test-aaaa", IP: netip.MustParseAddr("2001:db8::1"), TTL: TTL1h}},
		{"CNAME", libdns.CNAME{Name: "test-cname", Target: "example.com", TTL: TTL1h}},
		{"MX", libdns.MX{Name: "test-mx", Preference: 10, Target: "mail.example.com", TTL: TTL1h}},
		{"NS", libdns.NS{Name: "test-ns", Target: "ns1.example.com", TTL: TTL1h}},
		{"ALIAS", ALIAS{Name: "test-alias", Target: "example.com", TTL: TTL1h}},
		{"TXT", libdns.TXT{Name: "test-txt", Text: "hello world", TTL: TTL1h}},
		{"SRV", libdns.SRV{Service: "sip", Transport: "tcp", Name: "test-srv", Priority: 10, Weight: 20, Port: 5060, Target: "sipserver.example.com", TTL: TTL1h}},
		{"CAA", libdns.CAA{Name: "test-caa", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: TTL1h}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			added, err := provider.AppendRecords(ctx, zone, []libdns.Record{c.record})
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			if len(added) != 1 {
				t.Fatalf("expected 1 record added, got %d", len(added))
			}
			got := added[0]
			if recordID(got) == "" {
				t.Fatal("appended record has no ID")
			}
			if !sameRecord(got, c.record) {
				t.Fatalf("appended mismatch: want %q, got %q", c.record.RR().Data, got.RR().Data)
			}

			records, err := provider.GetRecords(ctx, zone)
			if err != nil {
				t.Fatalf("get records: %v", err)
			}
			var found libdns.Record
			for _, r := range records {
				if recordID(r) == recordID(got) {
					found = r
					break
				}
			}
			if found == nil {
				t.Fatalf("record %s not found after append", c.name)
			}
			if !sameRecord(found, c.record) {
				t.Fatalf("readback mismatch: want name=%q data=%q, got name=%q data=%q",
					c.record.RR().Name, c.record.RR().Data, found.RR().Name, found.RR().Data)
			}

			deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{found})
			if err != nil {
				t.Fatalf("delete: %v", err)
			}
			if len(deleted) != 1 {
				t.Fatalf("expected 1 record deleted, got %d", len(deleted))
			}

			records, err = provider.GetRecords(ctx, zone)
			if err != nil {
				t.Fatalf("get records after delete: %v", err)
			}
			for _, r := range records {
				if recordID(r) == recordID(got) {
					t.Fatalf("record %s still present after delete", c.name)
				}
			}
		})
	}
}

func TestSetInvalidTTLtoValid(t *testing.T) {
	provider.UnsupportedTTLisError = false
	cases := []struct {
		ttl      time.Duration
		expected time.Duration
	}{
		{0, TTL1m},
		{1 * time.Second, TTL1m},
		{1 * time.Minute, TTL1m},
		{1 * time.Hour, TTL1h},
		{1*time.Hour + 1*time.Minute, TTL6h},
		{30 * TTL24h, TTL30d},
		{31 * TTL24h, TTL30d},
		{100 * TTL24h, TTL30d},
	}
	for _, c := range cases {
		ttl, err := provider.getRecordTTL(c.ttl)
		if err != nil {
			t.Fatal(err)
		}
		if ttl != c.expected {
			t.Fatalf("expected %s, got %s", c.expected, ttl)
		}
	}
}

func TestAddRecordsInvalidTTL(t *testing.T) {
	records := []libdns.Record{
		libdns.Address{Name: "valid", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL12h},
		libdns.Address{Name: "invalid", IP: netip.MustParseAddr("127.0.0.1"), TTL: 69 * time.Second},
	}
	provider.UnsupportedTTLisError = true
	_, err := provider.AppendRecords(ctx, zone, records)
	if err == nil {
		t.Fatal("AppendRecords succeeded with invalid TTL")
	}
	if strings.Contains(err.Error(), "unsupported TTL value:") {
		t.Logf("AppendRecords failed as expected: %s", err)
	} else {
		t.Fatal(err)
	}
}

func TestAddRecords(t *testing.T) {
	records := []libdns.Record{
		libdns.Address{Name: "test", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL1m},
		libdns.Address{Name: "test2", IP: netip.MustParseAddr("127.0.0.2"), TTL: TTL1m},
		libdns.Address{Name: "test", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL1m},
	}

	added, err := provider.AppendRecords(ctx, zone, records)
	if err != nil {
		t.Fatal(err)
	}

	if len(added) != len(records) {
		t.Fatalf("expected %d records to be added, got %d", len(records), len(added))
	}

	for i, record := range added {
		if recordID(record) == "" {
			t.Fatalf("record %s ID not set", record.RR().Name)
		}

		if !sameRecord(record, records[i]) {
			t.Fatalf("expected %v, got %v", records[i], record)
		}
	}

	if recordID(added[0]) == recordID(added[2]) {
		t.Fatalf("expected IDs to be different, got %s", recordID(added[0]))
	}
}

func TestDeleteRecords(t *testing.T) {
	newRecords := []libdns.Record{
		libdns.Address{Name: "test", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL1m},
	}

	added, err := provider.AppendRecords(ctx, zone, newRecords)
	if err != nil || len(added) != 1 {
		t.Fatal(err)
	}
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	foundInRecords := false
	for _, record := range records {
		if recordID(record) == recordID(added[0]) {
			foundInRecords = true
			break
		}
	}
	if !foundInRecords {
		t.Fatalf("record not found in records")
	}

	deleted, err := provider.DeleteRecords(ctx, zone, added)
	if err != nil {
		t.Fatal(err)
	}

	if len(deleted) != len(added) {
		t.Fatalf("expected %d records to be deleted, got %d", len(added), len(deleted))
	}
	if recordID(deleted[0]) != recordID(added[0]) {
		t.Fatalf("expected ID %s, got %s", recordID(added[0]), recordID(deleted[0]))
	}

	records, err = provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	foundInRecords = false
	for _, record := range records {
		if recordID(record) == recordID(added[0]) {
			foundInRecords = true
			break
		}
	}
	if foundInRecords {
		t.Fatalf("record found in records")
	}
}

// TestDeleteNonexistentRecords verifies the libdns contract that deleting
// records which are not in the zone is silently ignored (no error, nothing
// returned), both when targeted by a bogus ID and by content.
func TestDeleteNonexistentRecords(t *testing.T) {
	records := []libdns.Record{
		libdns.Address{
			Name:         "nonexistent",
			IP:           netip.MustParseAddr("127.0.0.1"),
			TTL:          TTL1m,
			ProviderData: "000000",
		},
		libdns.Address{Name: "alsomissing", IP: netip.MustParseAddr("127.0.0.2"), TTL: TTL1m},
	}

	rec, err := provider.DeleteRecords(ctx, zone, records)
	if err != nil {
		t.Fatalf("expected nil error for nonexistent records, got %s", err)
	}
	if len(rec) != 0 {
		t.Fatalf("expected 0 records to be deleted, got %d", len(rec))
	}
}

func TestAppendDuplicateCNAME(t *testing.T) {
	records := []libdns.Record{
		libdns.CNAME{Name: "test-cname", Target: "example1.com", TTL: TTL1m},
		libdns.CNAME{Name: "test-cname", Target: "example2.com", TTL: TTL1m},
	}
	rec, err := provider.AppendRecords(ctx, zone, records)
	// Expected: failed to append records: failed to create record: server did not confirm creation
	if err == nil {
		t.Fatal("AppendRecords succeeded with duplicate CNAME names")
	}
	if !strings.Contains(err.Error(), "failed to create record") {
		t.Fatalf("expected 'failed to create record', got %s", err)
	}

	if len(rec) != 1 || rec[0].RR().Data != "example1.com" {
		t.Fatalf("expected 1 record added with target example1.com, got %v", rec)
	}

	// Cleanup the one that was added.
	if _, err := provider.DeleteRecords(ctx, zone, rec); err != nil {
		t.Fatal(err)
	}
}

// TestDeleteByContent deletes a record identified purely by its content (no
// ProviderData), and TestDeleteWildcard deletes by name only using an RR with
// empty type/ttl/value as wildcards.
func TestDeleteByContent(t *testing.T) {
	add, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-del", IP: netip.MustParseAddr("203.0.113.5"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.DeleteRecords(ctx, zone, add)

	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-del", IP: netip.MustParseAddr("203.0.113.5"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 record deleted, got %d", len(deleted))
	}
	if recordID(deleted[0]) != recordID(add[0]) {
		t.Fatalf("deleted wrong record: %s vs %s", recordID(deleted[0]), recordID(add[0]))
	}
}

func TestDeleteWildcard(t *testing.T) {
	add, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-wild", IP: netip.MustParseAddr("203.0.113.6"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.DeleteRecords(ctx, zone, add)

	// Name only; empty type/ttl/value act as wildcards.
	deleted, err := provider.DeleteRecords(ctx, zone, []libdns.Record{
		libdns.RR{Name: "test-wild"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 record deleted, got %d", len(deleted))
	}
}

// TestSetRecordsReplace verifies the RRset-replacement semantics of SetRecords:
// after the call, the only records for an input (name, type) pair are those
// provided, so pre-existing siblings are removed.
func TestSetRecordsReplace(t *testing.T) {
	_, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.1"), TTL: TTL1m},
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.2"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}

	set, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.3"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || set[0].RR().Data != "203.0.113.3" {
		t.Fatalf("unexpected set result: %v", set)
	}

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range records {
		if r.RR().Name == "test-set" && r.RR().Type == "A" {
			got = append(got, r.RR().Data)
		}
	}
	if len(got) != 1 || got[0] != "203.0.113.3" {
		t.Fatalf("expected only [203.0.113.3] for test-set/A, got %v", got)
	}

	// Cleanup.
	if _, err := provider.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "test-set"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSetRecordsReplaceMultiple(t *testing.T) {
	_, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.1"), TTL: TTL1m},
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.2"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}

	set, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.3"), TTL: TTL1m},
		libdns.Address{Name: "test-set", IP: netip.MustParseAddr("203.0.113.4"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("expected 2 records set, got %d", len(set))
	}
	if set[0].RR().Data != "203.0.113.3" || set[1].RR().Data != "203.0.113.4" {
		t.Fatalf("unexpected set result: %v", set)
	}

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range records {
		if r.RR().Name == "test-set" && r.RR().Type == "A" {
			got = append(got, r.RR().Data)
		}
	}
	if len(got) != 2 || got[0] != "203.0.113.3" || got[1] != "203.0.113.4" {
		t.Fatalf("expected [203.0.113.3 203.0.113.4] for test-set/A, got %v", got)
	}

	// Cleanup.
	if _, err := provider.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "test-set"}}); err != nil {
		t.Fatal(err)
	}
}

// TestSetRecordsUpdateAndAdd verifies that SetRecords updates an existing record
// in place when its (name, type) already exists, and creates records that do not.
func TestSetRecordsUpdateAndAdd(t *testing.T) {
	add, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-upd", IP: netip.MustParseAddr("203.0.113.1"), TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}

	set, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-upd", IP: netip.MustParseAddr("203.0.113.9"), TTL: TTL5m},
		libdns.TXT{Name: "test-upd", Text: "new", TTL: TTL1m},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 {
		t.Fatalf("expected 2 records set, got %d", len(set))
	}

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	var aData, aTTL, txt string
	aCount := 0
	for _, r := range records {
		rr := r.RR()
		if rr.Name != "test-upd" {
			continue
		}
		switch rr.Type {
		case "A":
			aCount++
			aData = rr.Data
			aTTL = rr.TTL.String()
			// The in-place update should preserve the original record ID.
			if recordID(r) != recordID(add[0]) {
				t.Fatalf("expected updated A to keep ID %s, got %s", recordID(add[0]), recordID(r))
			}
		case "TXT":
			txt = rr.Data
		}
	}
	if aCount != 1 || aData != "203.0.113.9" || aTTL != TTL5m.String() {
		t.Fatalf("A not updated in place: count=%d data=%s ttl=%s", aCount, aData, aTTL)
	}
	if txt != "new" {
		t.Fatalf("TXT not created, got %q", txt)
	}

	// Cleanup.
	if _, err := provider.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "test-upd"}}); err != nil {
		t.Fatal(err)
	}
}

// TestAppendNonCanonicalTTL is a regression test for the append path: matching a
// created record back against the zone used to compare the raw input TTL, which
// never equals the normalized TTL that Neoserv actually stores, so appending with
// an unsupported TTL (such as the zero value) failed even though the create
// succeeded. It verifies the append succeeds and that the returned and stored
// records carry the normalized TTL.
func TestAppendNonCanonicalTTL(t *testing.T) {
	provider.UnsupportedTTLisError = false

	// TTL 0 (the zero value) is bumped up to the smallest supported value, TTL1m.
	added, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-ttl-append", IP: netip.MustParseAddr("203.0.113.20"), TTL: 0},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(added) != 1 {
		t.Fatalf("expected 1 record added, got %d", len(added))
	}
	defer provider.DeleteRecords(ctx, zone, added)

	if recordID(added[0]) == "" {
		t.Fatal("appended record has no ID")
	}
	if added[0].RR().TTL != TTL1m {
		t.Fatalf("expected normalized TTL %s in result, got %s", TTL1m, added[0].RR().TTL)
	}

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("get records: %v", err)
	}
	var found libdns.Record
	for _, r := range records {
		if recordID(r) == recordID(added[0]) {
			found = r
			break
		}
	}
	if found == nil {
		t.Fatal("record not found after append")
	}
	if found.RR().TTL != TTL1m {
		t.Fatalf("expected stored TTL %s, got %s", TTL1m, found.RR().TTL)
	}
}

// TestSetRecordsNormalizesTTL verifies that when SetRecords updates a record in
// place with a non-canonical TTL, it stores and reports the normalized TTL while
// preserving the record's ID.
func TestSetRecordsNormalizesTTL(t *testing.T) {
	provider.UnsupportedTTLisError = false

	add, err := provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-ttl-set", IP: netip.MustParseAddr("203.0.113.21"), TTL: TTL1h},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	defer provider.DeleteRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "test-ttl-set"}})

	// A new value with a non-canonical TTL (0 -> TTL1m) forces an in-place update
	// rather than an exact-match keep.
	set, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.Address{Name: "test-ttl-set", IP: netip.MustParseAddr("203.0.113.22"), TTL: 0},
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if len(set) != 1 {
		t.Fatalf("expected 1 record set, got %d", len(set))
	}
	if set[0].RR().TTL != TTL1m {
		t.Fatalf("expected reported TTL %s, got %s", TTL1m, set[0].RR().TTL)
	}
	if recordID(set[0]) != recordID(add[0]) {
		t.Fatalf("expected in-place update to keep ID %s, got %s", recordID(add[0]), recordID(set[0]))
	}

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("get records: %v", err)
	}
	var found libdns.Record
	for _, r := range records {
		if r.RR().Name == "test-ttl-set" && r.RR().Type == "A" {
			found = r
			break
		}
	}
	if found == nil {
		t.Fatal("record not found after set")
	}
	if found.RR().TTL != TTL1m {
		t.Fatalf("expected stored TTL %s, got %s", TTL1m, found.RR().TTL)
	}
	if found.RR().Data != "203.0.113.22" {
		t.Fatalf("expected updated data 203.0.113.22, got %s", found.RR().Data)
	}
}

func TestDeleteTestingRecords(t *testing.T) {
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	toDelete := make([]libdns.Record, 0)
	for _, record := range records {
		name := record.RR().Name
		if strings.HasPrefix(name, "test") || strings.Contains(name, ".test") {
			toDelete = append(toDelete, record)
		}
	}

	if len(toDelete) == 0 {
		t.Skip("no testing records found")
	}

	deleted, err := provider.DeleteRecords(ctx, zone, toDelete)
	if err != nil {
		t.Fatal(err)
	}

	if len(deleted) != len(toDelete) {
		t.Fatalf("expected %d records to be deleted, got %d", len(toDelete), len(deleted))
	}

	for i, record := range deleted {
		if !sameRecord(record, toDelete[i]) {
			t.Fatalf("expected %v, got %v", toDelete[i], record)
		}
	}
}
