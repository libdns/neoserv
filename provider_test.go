package neoserv

import (
	"context"
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
	// correct credentials for the remaining tests.
	bad := Provider{Username: username, Password: "incorrect"}
	if err := bad.init(); err != nil {
		t.Fatal(err)
	}
	err := bad.authenticate(ctx)
	if err == nil {
		t.Fatal("authentication succeeded with incorrect password")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected 'authentication failed', got %s", err)
	}

	t.Logf("Authentication failed as expected: %s", err)
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

func TestDeleteNonexistentRecords(t *testing.T) {
	records := []libdns.Record{
		libdns.Address{
			Name:         "nonexistent",
			IP:           netip.MustParseAddr("127.0.0.1"),
			TTL:          TTL1m,
			ProviderData: "000000",
		},
	}

	rec, err := provider.DeleteRecords(ctx, zone, records)
	if err == nil {
		t.Fatal("DeleteRecords succeeded with nonexistent record")
	}
	if len(rec) != 0 {
		t.Fatalf("expected 0 records to be deleted, got %d", len(rec))
	}
	if !strings.Contains(err.Error(), "record not found") {
		t.Fatalf("expected 'record not found', got %s", err)
	}
}

func TestUpdateRecords(t *testing.T) {
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	var toEditID string
	for _, record := range records {
		if record.RR().Name == "test" {
			toEditID = recordID(record)
			break
		}
	}

	if toEditID == "" {
		newr, err := provider.AppendRecords(ctx, zone, []libdns.Record{
			libdns.Address{Name: "test", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL1m},
		})
		if err != nil {
			t.Fatal(err)
		}
		toEditID = recordID(newr[0])
	}

	newRecords := []libdns.Record{
		libdns.Address{Name: "test-created", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL1m},
		libdns.Address{Name: "test-edited", IP: netip.MustParseAddr("127.0.0.1"), TTL: TTL5m, ProviderData: toEditID},
	}

	updated, err := provider.SetRecords(ctx, zone, newRecords)
	if err != nil {
		t.Fatal(err)
	}

	if len(updated) != len(newRecords) {
		t.Fatalf("expected %d records to be updated, got %d", len(newRecords), len(updated))
	}

	for i, record := range updated {
		if !sameRecord(record, newRecords[i]) {
			t.Fatalf("expected %v, got %v", newRecords[i], record)
		}
	}
}

func TestDeleteTestingRecords(t *testing.T) {
	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	toDelete := make([]libdns.Record, 0)
	for _, record := range records {
		if strings.HasPrefix(record.RR().Name, "test") {
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
