// Package neoserv implements a DNS record management client compatible
// with the libdns interfaces for Neoserv.
package neoserv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// ErrLoginRateLimited is returned when Neoserv has temporarily blocked login
// attempts for the account because there were too many tries. The block clears
// after a while (about an hour); callers can detect it with errors.Is and back
// off rather than retrying. A still-valid cached session is unaffected, since it
// does not require logging in.
var ErrLoginRateLimited = errors.New("login rate limited: too many login attempts, try again later")

// Provider facilitates DNS record manipulation with Neoserv.si.
type Provider struct {
	// Email used to authenticate with moj.neoserv.si
	Username string `json:"username,omitempty"`
	// Password used to authenticate with moj.neoserv.si
	Password string `json:"password,omitempty"`

	// UnsupportedTTLisError determines whether an unsupported TTL value should be treated as an error.
	// If set to true, the provider will return an error if an unsupported TTL value is requested.
	// If set to false, the provider will set the TTL to the nearest supported value that is at least the requested
	// value.
	UnsupportedTTLisError bool `json:"unsupported_ttl_is_error,omitempty"`

	// SessionCachePath is the file used to persist the login session cookie between
	// runs, which avoids Neoserv's login rate limit. When empty, a per-account file
	// in the OS temp directory is used. Ignored when DisableSessionCache is true.
	SessionCachePath string `json:"session_cache_path,omitempty"`

	// DisableSessionCache opts out of persisting and reusing the login session on
	// disk. When true, the provider always logs in with the username and password.
	DisableSessionCache bool `json:"disable_session_cache,omitempty"`

	// client is the HTTP client used to communicate with the Neoserv API.
	client *http.Client
	// zoneIdCache is a map of zone names to their corresponding zone IDs.
	// This is used to avoid making unnecessary API calls to get the zone ID.
	zoneIdCache map[string]string

	// mutex guards the client, the zone ID cache, and the zoneLocks map.
	mutex sync.Mutex
	// authMu serializes re-authentication when an in-flight request finds the
	// session expired, so concurrent callers do not all log in at once.
	authMu sync.Mutex
	// zoneLocks holds a per-zone mutex used to serialize the read-modify-write
	// sequences in the mutating record methods, so concurrent callers do not
	// corrupt each other's view of the zone.
	zoneLocks map[string]*sync.Mutex
}

// zoneLock returns the mutex dedicated to the given zone, creating it on first
// use. Different zones get independent locks so unrelated zones are not
// serialized against each other.
func (p *Provider) zoneLock(zone string) *sync.Mutex {
	key := strings.TrimSuffix(zone, ".")
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.zoneLocks == nil {
		p.zoneLocks = make(map[string]*sync.Mutex)
	}
	lk := p.zoneLocks[key]
	if lk == nil {
		lk = &sync.Mutex{}
		p.zoneLocks[key] = lk
	}
	return lk
}

// Neoserv API does not support all TTL values. The following are the supported TTL values.
// Check Provider.UnsupportedTTLisError to determine how unsupported TTL values are handled.
const (
	TTL1m  = 1 * time.Minute
	TTL5m  = 5 * time.Minute
	TTL10m = 10 * time.Minute
	TTL15m = 15 * time.Minute
	TTL30m = 30 * time.Minute
	TTL1h  = 1 * time.Hour
	TTL6h  = 6 * time.Hour
	TTL12h = 12 * time.Hour
	TTL24h = 24 * time.Hour
	TTL2d  = 2 * 24 * time.Hour
	TTL3d  = 3 * 24 * time.Hour
	TTL7d  = 7 * 24 * time.Hour
	TTL14d = 14 * 24 * time.Hour
	TTL30d = 30 * 24 * time.Hour
)

var (
	ValidTTLs = []time.Duration{
		TTL1m, TTL5m, TTL10m, TTL15m, TTL30m, TTL1h, TTL6h, TTL12h, TTL24h, TTL2d, TTL3d, TTL7d, TTL14d, TTL30d,
	}
)

// ALIAS is a Neoserv-specific DNS record type that is not defined by the libdns
// package. It behaves like a CNAME but is permitted at the zone apex, resolving
// to the address records of the Target. It satisfies the libdns.Record interface
// so it can be passed to and returned from the Provider's record methods.
type ALIAS struct {
	Name string
	TTL  time.Duration
	// Target is the canonical name the alias points to.
	Target string

	// ProviderData holds the Neoserv-assigned record ID. See the libdns package
	// godoc for details on this field.
	ProviderData any
}

// RR returns the libdns resource record representation of the ALIAS record.
func (a ALIAS) RR() libdns.RR {
	return libdns.RR{Name: a.Name, TTL: a.TTL, Type: "ALIAS", Data: a.Target}
}

// ListZones returns the list of DNS zones available to the account.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	return p.listZones(ctx)
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.getRecords(ctx, zone)
}

// AppendRecords adds records to the zone. It returns the records that were added.
// Any ProviderData (record ID) on the input is ignored; appended records are
// always created anew.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	lock := p.zoneLock(zone)
	lock.Lock()
	defer lock.Unlock()
	return p.appendRecords(ctx, zone, records)
}

// appendRecords is the unlocked implementation of AppendRecords. Callers must
// hold the zone lock.
func (p *Provider) appendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, record := range records {
		if _, err := p.getRecordTTL(record.RR().TTL); err != nil {
			return nil, fmt.Errorf("failed to append records: %w", err)
		}
	}

	// Because Neoserv does not return the ID of the newly added record(s), we identify
	// new records by comparing the record list before and after the append operation.
	appendedRecords := make([]libdns.Record, 0, len(records))

	oldRecords, err := p.getRecords(ctx, zone)
	if err != nil {
		return appendedRecords, fmt.Errorf("failed to append records: %w", err)
	}

	for _, record := range records {
		if err := p.createRecord(ctx, zone, record); err != nil {
			return appendedRecords, fmt.Errorf("failed to append records: %w", err)
		}
		appendedRecords = append(appendedRecords, record)
	}

	afterRecords, err := p.getRecords(ctx, zone)
	if err != nil {
		return appendedRecords, fmt.Errorf("failed to append records: %w", err)
	}

	oldRecordIDs := make(map[string]struct{}, len(oldRecords))
	for _, record := range oldRecords {
		oldRecordIDs[recordID(record)] = struct{}{}
	}

	newRecords := make([]libdns.Record, 0, len(records))
	for _, record := range afterRecords {
		if _, ok := oldRecordIDs[recordID(record)]; !ok {
			newRecords = append(newRecords, record)
		}
	}

	for i, appendedRecord := range appendedRecords {
		matchingIdx := -1
		for j, newRecord := range newRecords {
			if sameRecord(appendedRecord, newRecord) {
				matchingIdx = j
				break
			}
		}
		if matchingIdx == -1 {
			return appendedRecords, fmt.Errorf("failed to append records: record %s not found in new records", appendedRecord.RR().Name)
		}
		appendedRecords[i] = newRecords[matchingIdx]
		newRecords[matchingIdx] = newRecords[len(newRecords)-1]
		newRecords = newRecords[:len(newRecords)-1]
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone so that, for every (name, type) pair
// present in the input, the only records of that pair in the zone are the ones
// provided. Records of other (name, type) pairs are left untouched. It returns
// the records that were set, in input order.
//
// Existing records that match an input record exactly are kept as-is; remaining
// existing records in an affected RRset are reused via an in-place update where
// possible (preserving their ID), and otherwise created or deleted to reach the
// desired state. SetRecords is not atomic: a mid-operation error may leave the
// zone partially modified.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	lock := p.zoneLock(zone)
	lock.Lock()
	defer lock.Unlock()

	for _, record := range records {
		if _, err := p.getRecordTTL(record.RR().TTL); err != nil {
			return nil, fmt.Errorf("failed to set records: %w", err)
		}
	}

	current, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to set records: %w", err)
	}
	currentByKey := make(map[string][]libdns.Record)
	for _, r := range current {
		currentByKey[rrKey(r)] = append(currentByKey[rrKey(r)], r)
	}

	// Group the input by RRset, remembering each record's original index so the
	// output can be returned in input order.
	type item struct {
		idx int
		rec libdns.Record
	}
	inputByKey := make(map[string][]item)
	keyOrder := make([]string, 0)
	for i, r := range records {
		k := rrKey(r)
		if _, seen := inputByKey[k]; !seen {
			keyOrder = append(keyOrder, k)
		}
		inputByKey[k] = append(inputByKey[k], item{idx: i, rec: r})
	}

	out := make([]libdns.Record, len(records))
	toAppend := make([]item, 0)
	toDelete := make([]libdns.Record, 0)

	for _, k := range keyOrder {
		items := inputByKey[k]
		existing := currentByKey[k]
		usedExisting := make([]bool, len(existing))
		matched := make([]bool, len(items))

		// Pass 1: keep exact content matches as-is (they already have an ID).
		for i, it := range items {
			for j, e := range existing {
				if !usedExisting[j] && sameRecord(it.rec, e) {
					usedExisting[j] = true
					matched[i] = true
					out[it.idx] = e
					break
				}
			}
		}

		// Pass 2: reconcile the leftovers. Reuse leftover existing records by
		// updating them in place; append when there are more desired than
		// existing; delete when there are more existing than desired.
		leftoverExisting := make([]int, 0)
		for j := range existing {
			if !usedExisting[j] {
				leftoverExisting = append(leftoverExisting, j)
			}
		}
		next := 0
		for i, it := range items {
			if matched[i] {
				continue
			}
			if next < len(leftoverExisting) {
				e := existing[leftoverExisting[next]]
				next++
				updated := withRecordID(it.rec, recordID(e))
				if err := p.updateRecord(ctx, zone, updated); err != nil {
					return nil, fmt.Errorf("failed to set records: %w", err)
				}
				out[it.idx] = updated
			} else {
				toAppend = append(toAppend, it)
			}
		}
		for ; next < len(leftoverExisting); next++ {
			toDelete = append(toDelete, existing[leftoverExisting[next]])
		}
	}

	if len(toAppend) > 0 {
		recs := make([]libdns.Record, len(toAppend))
		for i, it := range toAppend {
			recs[i] = it.rec
		}
		added, err := p.appendRecords(ctx, zone, recs)
		if err != nil {
			return nil, fmt.Errorf("failed to set records: %w", err)
		}
		for i, it := range toAppend {
			out[it.idx] = added[i]
		}
	}

	for _, r := range toDelete {
		if err := p.deleteRecord(ctx, zone, r); err != nil {
			return nil, fmt.Errorf("failed to set records: %w", err)
		}
	}

	return out, nil
}

// DeleteRecords deletes records from the zone that match the input and returns
// the records that were actually deleted. Input records that do not exist in the
// zone are silently ignored.
//
// Matching is by content: the Name must match, and the Type, TTL, and Value are
// each matched only when non-empty (an empty Type, zero TTL, or empty Value acts
// as a wildcard for that field). When an input record carries ProviderData (a
// record ID), that ID is used to target exactly one record instead.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	lock := p.zoneLock(zone)
	lock.Lock()
	defer lock.Unlock()

	current, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to delete records: %w", err)
	}

	deletedIDs := make(map[string]struct{})
	removed := make([]libdns.Record, 0, len(records))
	for _, input := range records {
		id := recordID(input)
		for _, cur := range current {
			curID := recordID(cur)
			if _, done := deletedIDs[curID]; done {
				continue
			}
			var match bool
			if id != "" {
				match = curID == id
			} else {
				match = recordMatches(input, cur)
			}
			if !match {
				continue
			}
			if err := p.deleteRecord(ctx, zone, cur); err != nil {
				return removed, fmt.Errorf("failed to delete records: %w", err)
			}
			deletedIDs[curID] = struct{}{}
			removed = append(removed, cur)
		}
	}

	return removed, nil
}

// Interface guards
var (
	_ libdns.ZoneLister     = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
