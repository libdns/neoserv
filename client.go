package neoserv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/libdns/libdns"
)

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

const (
	urlBase          = "https://moj.neoserv.si"
	urlLogin         = urlBase + "/login"
	urlServices      = urlBase + "/services?type=domains"
	urlDomainRecords = urlBase + "/domains/%s/records"
	urlLivewire      = urlBase + "/livewire/update"
)

var (
	urlBaseP   = mustParseURL(urlBase)
	domainIDRe = regexp.MustCompile(`/domains/(\d+)`)
)

// Livewire request/response types.
type livewirePayload struct {
	Token      string              `json:"_token"`
	Components []livewireComponent `json:"components"`
}

type livewireComponent struct {
	Snapshot string         `json:"snapshot"`
	Updates  map[string]any `json:"updates"`
	Calls    []livewireCall `json:"calls"`
}

type livewireCall struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type livewireResponse struct {
	Components []struct {
		Effects struct {
			Dispatches []struct {
				Name string `json:"name"`
			} `json:"dispatches"`
		} `json:"effects"`
	} `json:"components"`
}

func (r livewireResponse) hasDispatch(name string) bool {
	for _, comp := range r.Components {
		for _, d := range comp.Effects.Dispatches {
			if d.Name == name {
				return true
			}
		}
	}
	return false
}

// snapshotRecordData is the record object inside a domain-record-row Livewire snapshot.
// The wire protocol wraps values in arrays with PHP type metadata; Type[0] is the type string.
type snapshotRecordData struct {
	ID       string            `json:"id"`
	Type     []json.RawMessage `json:"type"`
	Host     string            `json:"host"`
	Record   string            `json:"record"`
	TTL      json.RawMessage   `json:"ttl"`
	Priority json.RawMessage   `json:"priority"`
	Weight   json.RawMessage   `json:"weight"`
	Port     json.RawMessage   `json:"port"`
	CAAFlag  json.RawMessage   `json:"caa_flag"`
	CAAType  string            `json:"caa_type"`
	CAAValue string            `json:"caa_value"`
	Locked   bool              `json:"locked"`
}

// neoservForm holds the decoded form fields needed for create/update Livewire calls.
type neoservForm struct {
	recordType string
	host       string
	value      string
	ttl        int
	priority   int
	weight     int
	port       int
	caaFlag    int
	caaType    string
}

// unknownRecord is returned for DNS types not defined by the libdns package (e.g. ALIAS, WR).
// It stores the provider record ID in providerData so that deletes still work.
type unknownRecord struct {
	name         string
	ttl          time.Duration
	recordType   string
	data         string
	providerData any
}

func (r unknownRecord) RR() libdns.RR {
	return libdns.RR{Name: r.name, TTL: r.ttl, Type: r.recordType, Data: r.data}
}

// pageData holds the Livewire component snapshots and CSRF token fetched from the records page.
type pageData struct {
	byName map[string][]string // component name → raw JSON snapshot strings
	csrf   string
}

// init initializes the Provider with an HTTP client and zone ID cache.
// Expects the caller to hold the mutex.
func (p *Provider) init() error {
	if p.client != nil {
		return nil
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	p.client = &http.Client{Jar: jar}
	p.zoneIdCache = make(map[string]string)
	return nil
}

// isAuthenticated reports whether a Laravel session cookie is present.
func (p *Provider) isAuthenticated() bool {
	for _, cookie := range p.client.Jar.Cookies(urlBaseP) {
		if cookie.Name == "moj_session" {
			return true
		}
	}
	return false
}

// authenticate ensures the provider is logged in to moj.neoserv.si.
// Expects the caller to hold the mutex.
func (p *Provider) authenticate(ctx context.Context) error {
	if err := p.init(); err != nil {
		return fmt.Errorf("failed to initialize provider: %w", err)
	}

	if p.isAuthenticated() {
		return nil
	}

	// Before logging in, try to reuse an existing session to avoid the login rate limit.
	if p.reuseSession(ctx) {
		return nil
	}

	// Step 1: GET /login to collect cookies and the CSRF token.
	loginResp, err := p.client.Get(urlLogin)
	if err != nil {
		return fmt.Errorf("failed to fetch login page: %w", err)
	}
	defer loginResp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(loginResp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse login page: %w", err)
	}

	csrfToken := doc.Find("input[name='_token']").AttrOr("value", "")
	if csrfToken == "" {
		return fmt.Errorf("failed to find CSRF token on login page")
	}

	// Step 2: POST /login with credentials.
	form := url.Values{}
	form.Set("_token", csrfToken)
	form.Set("email", p.Username)
	form.Set("password", p.Password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlLogin, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", urlLogin)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform login request: %w", err)
	}
	defer resp.Body.Close()

	// Laravel redirects back to /login on bad credentials; any other path means success.
	if strings.HasSuffix(resp.Request.URL.Path, "/login") {
		return fmt.Errorf("authentication failed")
	}

	// Persist the fresh session so later runs can skip the login.
	if !p.DisableSessionCache {
		_ = p.saveCachedSession()
	}
	return nil
}

// domainEntry pairs a zone name with its numeric cart ID from the services page.
type domainEntry struct {
	name string // zone name without trailing dot, e.g. "example.com"
	id   string // numeric cart ID
}

// fetchDomains returns all domains visible on the services page.
// Expects the caller to hold the mutex and to have authenticated.
func (p *Provider) fetchDomains(ctx context.Context) ([]domainEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlServices, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build services page request: %w", err)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get services page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("services page returned status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse services page: %w", err)
	}

	// Each domain is rendered in its own container that holds both a link to
	// /domains/<id> and the domain name as plain text, but they can be far apart
	// in the DOM. For every domain link we walk up the ancestor chain to the
	// shallowest container whose text contains a domain name and pair it with the ID.
	var domains []domainEntry
	seen := make(map[string]struct{})
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		m := domainIDRe.FindStringSubmatch(href)
		if m == nil {
			return
		}
		id := m[1]
		if _, ok := seen[id]; ok {
			return
		}
		node := s
		for depth := 0; depth < 12 && node.Length() > 0; depth++ {
			if name := firstDomainName(node.Text()); name != "" {
				seen[id] = struct{}{}
				domains = append(domains, domainEntry{name: name, id: id})
				break
			}
			node = node.Parent()
		}
	})

	return domains, nil
}

// getZoneID returns the numeric cart ID for the given zone name.
// Results are cached. Expects no mutex held by the caller.
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.authenticate(ctx); err != nil {
		return "", fmt.Errorf("failed to get zone ID: %w", err)
	}

	if id, ok := p.zoneIdCache[zone]; ok {
		return id, nil
	}

	domains, err := p.fetchDomains(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get zone ID: %w", err)
	}

	zoneName := strings.TrimSuffix(zone, ".")
	for _, d := range domains {
		if strings.EqualFold(d.name, zoneName) {
			p.zoneIdCache[zone] = d.id
			return d.id, nil
		}
	}
	return "", fmt.Errorf("failed to get zone ID: zone %s not found", zone)
}

// listZones returns all zones available to the account.
// Expects no mutex held by the caller.
func (p *Provider) listZones(ctx context.Context) ([]libdns.Zone, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := p.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	domains, err := p.fetchDomains(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	zones := make([]libdns.Zone, 0, len(domains))
	for _, d := range domains {
		zones = append(zones, libdns.Zone{Name: d.name + "."})
	}
	return zones, nil
}

// domainTokenRe matches a DNS domain name (with an alphabetic TLD), used to pick
// the zone name out of a container's visible text. Requiring an alphabetic TLD
// avoids matching IP addresses such as "1.2.2.2".
var domainTokenRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

// firstDomainName returns the first domain-like token in text, or "" if none.
func firstDomainName(text string) string {
	for _, field := range strings.Fields(strings.ToLower(text)) {
		t := strings.Trim(field, ".,:;()[]{}\"'")
		if domainTokenRe.MatchString(t) {
			return t
		}
	}
	return ""
}

// getPageSnapshots fetches /domains/<cartId>/records and returns all Livewire component
// snapshots grouped by component name, plus the page CSRF token.
func (p *Provider) getPageSnapshots(ctx context.Context, zone string) (pageData, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return pageData{}, fmt.Errorf("failed to get page snapshots: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(urlDomainRecords, zoneID), nil)
	if err != nil {
		return pageData{}, fmt.Errorf("failed to build records page request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return pageData{}, fmt.Errorf("failed to get records page: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pageData{}, fmt.Errorf("records page returned status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return pageData{}, fmt.Errorf("failed to parse records page: %w", err)
	}

	result := pageData{byName: make(map[string][]string)}

	// Extract CSRF token.
	result.csrf = doc.Find("input[name='_token']").First().AttrOr("value", "")
	if result.csrf == "" {
		result.csrf = doc.Find("meta[name='csrf-token']").AttrOr("content", "")
	}

	// Extract all wire:snapshot attributes.
	doc.Find("[wire\\:snapshot]").Each(func(_ int, s *goquery.Selection) {
		raw, exists := s.Attr("wire:snapshot")
		if !exists {
			return
		}
		raw = html.UnescapeString(raw)

		var envelope struct {
			Memo struct {
				Name string `json:"name"`
			} `json:"memo"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			return
		}
		result.byName[envelope.Memo.Name] = append(result.byName[envelope.Memo.Name], raw)
	})

	return result, nil
}

// livewireRequest sends a POST to /livewire/update and returns the decoded response.
func (p *Provider) livewireRequest(ctx context.Context, payload livewirePayload) (livewireResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return livewireResponse{}, fmt.Errorf("failed to marshal livewire payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlLivewire, bytes.NewReader(body))
	if err != nil {
		return livewireResponse{}, fmt.Errorf("failed to build livewire request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Livewire", "")
	req.Header.Set("Origin", urlBase)
	req.Header.Set("Referer", urlBase)

	resp, err := p.client.Do(req)
	if err != nil {
		return livewireResponse{}, fmt.Errorf("failed to perform livewire request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return livewireResponse{}, fmt.Errorf("livewire request returned status %d", resp.StatusCode)
	}

	var result livewireResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return livewireResponse{}, fmt.Errorf("failed to decode livewire response: %w", err)
	}
	return result, nil
}

// getRecords returns all records in the zone by parsing domain-record-row Livewire snapshots.
func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	page, err := p.getPageSnapshots(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get records: %w", err)
	}

	rows := page.byName["cart.domain.dns-record-row"]
	records := make([]libdns.Record, 0, len(rows))
	for _, raw := range rows {
		rec, err := parseRowSnapshot(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse record snapshot: %w", err)
		}
		records = append(records, rec)
	}
	return records, nil
}

// parseRowSnapshot extracts a libdns.Record from a single domain-record-row Livewire snapshot.
func parseRowSnapshot(raw string) (libdns.Record, error) {
	var envelope struct {
		Data struct {
			Record []json.RawMessage `json:"record"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot: %w", err)
	}
	if len(envelope.Data.Record) < 1 {
		return nil, fmt.Errorf("snapshot contains no record data")
	}

	var recData snapshotRecordData
	if err := json.Unmarshal(envelope.Data.Record[0], &recData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record data: %w", err)
	}
	return snapshotRecordToLibdns(recData)
}

// snapshotRecordToLibdns converts a parsed snapshot record into the appropriate libdns type.
func snapshotRecordToLibdns(r snapshotRecordData) (libdns.Record, error) {
	name := r.Host
	if name == "" {
		name = "@"
	}
	ttl := parseTTLRaw(r.TTL)

	var typeStr string
	if len(r.Type) > 0 {
		if err := json.Unmarshal(r.Type[0], &typeStr); err != nil {
			return nil, fmt.Errorf("failed to parse record type: %w", err)
		}
	}
	typeStr = strings.ToUpper(strings.TrimSpace(typeStr))

	id := r.ID

	switch typeStr {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(r.Record)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", r.Record, err)
		}
		return libdns.Address{Name: name, TTL: ttl, IP: ip, ProviderData: id}, nil
	case "CNAME":
		return libdns.CNAME{Name: name, TTL: ttl, Target: r.Record, ProviderData: id}, nil
	case "MX":
		prio := parsePriorityRaw(r.Priority)
		return libdns.MX{Name: name, TTL: ttl, Preference: prio, Target: r.Record, ProviderData: id}, nil
	case "SRV":
		// Neoserv stores the full "_service._transport.name" owner in Host. We keep
		// Service and Transport empty so SRV.RR() uses Name verbatim, preserving the
		// round trip regardless of how the underscored labels are structured.
		return libdns.SRV{
			Name:         name,
			TTL:          ttl,
			Priority:     parsePriorityRaw(r.Priority),
			Weight:       parsePriorityRaw(r.Weight),
			Port:         parsePriorityRaw(r.Port),
			Target:       r.Record,
			ProviderData: id,
		}, nil
	case "NS":
		return libdns.NS{Name: name, TTL: ttl, Target: r.Record, ProviderData: id}, nil
	case "ALIAS":
		return ALIAS{Name: name, TTL: ttl, Target: r.Record, ProviderData: id}, nil
	case "TXT":
		return libdns.TXT{Name: name, TTL: ttl, Text: r.Record, ProviderData: id}, nil
	case "CAA":
		// CAA rows carry their parts in dedicated fields rather than in Record.
		flag, _ := strconv.ParseUint(strings.Trim(string(r.CAAFlag), `"`), 10, 8)
		return libdns.CAA{Name: name, TTL: ttl, Flags: uint8(flag), Tag: r.CAAType, Value: r.CAAValue, ProviderData: id}, nil
	default:
		return unknownRecord{name: name, ttl: ttl, recordType: typeStr, data: r.Record, providerData: id}, nil
	}
}

// libdnsRecordToNeoservForm extracts the form fields needed for create/update Livewire calls.
func libdnsRecordToNeoservForm(r libdns.Record) neoservForm {
	rr := r.RR()
	host := rr.Name
	if host == "@" {
		host = ""
	}
	ttl := int(rr.TTL.Seconds())

	switch v := r.(type) {
	case libdns.Address:
		recType := "A"
		if v.IP.Is6() {
			recType = "AAAA"
		}
		return neoservForm{recordType: recType, host: host, value: v.IP.String(), ttl: ttl}
	case libdns.CNAME:
		return neoservForm{recordType: "CNAME", host: host, value: v.Target, ttl: ttl}
	case libdns.MX:
		return neoservForm{recordType: "MX", host: host, value: v.Target, ttl: ttl, priority: int(v.Preference)}
	case libdns.SRV:
		return neoservForm{recordType: "SRV", host: host, value: v.Target, ttl: ttl, priority: int(v.Priority), weight: int(v.Weight), port: int(v.Port)}
	case libdns.NS:
		return neoservForm{recordType: "NS", host: host, value: v.Target, ttl: ttl}
	case ALIAS:
		return neoservForm{recordType: "ALIAS", host: host, value: v.Target, ttl: ttl}
	case libdns.TXT:
		return neoservForm{recordType: "TXT", host: host, value: v.Text, ttl: ttl}
	case libdns.CAA:
		return neoservForm{recordType: "CAA", host: host, value: v.Value, ttl: ttl, caaFlag: int(v.Flags), caaType: v.Tag}
	default:
		return neoservForm{recordType: rr.Type, host: host, value: rr.Data, ttl: ttl}
	}
}

func parseTTLRaw(raw json.RawMessage) time.Duration {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return time.Duration(n) * time.Second
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if n, err := strconv.Atoi(s); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return 0
}

func parsePriorityRaw(raw json.RawMessage) uint16 {
	if len(raw) == 0 {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return uint16(n)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if n, err := strconv.Atoi(s); err == nil {
			return uint16(n)
		}
	}
	return 0
}

// createRecord adds a new record via the add-domain-record-dialog Livewire component.
func (p *Provider) createRecord(ctx context.Context, zone string, record libdns.Record) error {
	ttl, err := p.getRecordTTL(record.RR().TTL)
	if err != nil {
		return fmt.Errorf("failed to create record: %w", err)
	}

	page, err := p.getPageSnapshots(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to create record: %w", err)
	}

	dialogSnapshots := page.byName["cart.domain.create-dns-record-dialog"]
	if len(dialogSnapshots) == 0 {
		return fmt.Errorf("failed to create record: add-domain-record-dialog snapshot not found")
	}

	form := libdnsRecordToNeoservForm(record)
	form.ttl = int(ttl.Seconds())

	updates := map[string]any{
		"form.record_type": form.recordType,
		"form.host":        form.host,
		"form.record":      form.value,
		"form.ttl":         form.ttl,
		"form.priority":    form.priority,
		"form.weight":      form.weight,
		"form.port":        form.port,
		"show":             true,
	}
	if form.recordType == "CAA" {
		updates["form.caa_flag"] = form.caaFlag
		updates["form.caa_type"] = form.caaType
	}

	result, err := p.livewireRequest(ctx, livewirePayload{
		Token: page.csrf,
		Components: []livewireComponent{{
			Snapshot: dialogSnapshots[0],
			Updates:  updates,
			Calls:    []livewireCall{{Path: "", Method: "add", Params: []any{}}},
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to create record: %w", err)
	}
	if !result.hasDispatch("added") {
		return fmt.Errorf("failed to create record: server did not confirm creation")
	}
	return nil
}

// updateRecord updates an existing record via its domain-record-row Livewire component snapshot.
func (p *Provider) updateRecord(ctx context.Context, zone string, record libdns.Record) error {
	ttl, err := p.getRecordTTL(record.RR().TTL)
	if err != nil {
		return fmt.Errorf("failed to update record: %w", err)
	}

	page, err := p.getPageSnapshots(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to update record: %w", err)
	}

	id := recordID(record)
	rowSnapshots := page.byName["cart.domain.dns-record-row"]
	targetSnapshot := ""
	for _, raw := range rowSnapshots {
		var envelope struct {
			Data struct {
				Record []json.RawMessage `json:"record"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil || len(envelope.Data.Record) < 1 {
			continue
		}
		var recData snapshotRecordData
		if err := json.Unmarshal(envelope.Data.Record[0], &recData); err != nil {
			continue
		}
		if recData.ID == id {
			targetSnapshot = raw
			break
		}
	}
	if targetSnapshot == "" {
		return fmt.Errorf("failed to update record: snapshot for record ID %s not found", id)
	}

	form := libdnsRecordToNeoservForm(record)
	form.ttl = int(ttl.Seconds())

	updates := map[string]any{
		"form.host":      form.host,
		"form.record":    form.value,
		"form.ttl":       form.ttl,
		"form.priority":  form.priority,
		"form.weight":    form.weight,
		"form.port":      form.port,
		"showEditDialog": true,
	}
	if form.recordType == "CAA" {
		updates["form.caa_flag"] = form.caaFlag
		updates["form.caa_type"] = form.caaType
	}

	result, err := p.livewireRequest(ctx, livewirePayload{
		Token: page.csrf,
		Components: []livewireComponent{{
			Snapshot: targetSnapshot,
			Updates:  updates,
			Calls:    []livewireCall{{Path: "", Method: "save", Params: []any{}}},
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to update record: %w", err)
	}
	if !result.hasDispatch("modified") {
		return fmt.Errorf("failed to update record: server did not confirm update")
	}
	return nil
}

// deleteRecord removes a record via the domain-records-page Livewire component.
func (p *Provider) deleteRecord(ctx context.Context, zone string, record libdns.Record) error {
	page, err := p.getPageSnapshots(ctx, zone)
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}

	pageSnapshots := page.byName["cart.domain.dns-records-page"]
	if len(pageSnapshots) == 0 {
		return fmt.Errorf("failed to delete record: domain-records-page snapshot not found")
	}

	id := recordID(record)
	numericID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to delete record: invalid record ID %q: %w", id, err)
	}

	// Verify the record exists before attempting deletion.
	rowSnapshots := page.byName["cart.domain.dns-record-row"]
	found := false
	for _, raw := range rowSnapshots {
		var envelope struct {
			Data struct {
				Record []json.RawMessage `json:"record"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil || len(envelope.Data.Record) < 1 {
			continue
		}
		var recData snapshotRecordData
		if err := json.Unmarshal(envelope.Data.Record[0], &recData); err != nil {
			continue
		}
		if recData.ID == id {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("failed to delete record: record not found")
	}

	_, err = p.livewireRequest(ctx, livewirePayload{
		Token: page.csrf,
		Components: []livewireComponent{{
			Snapshot: pageSnapshots[0],
			Updates:  map[string]any{},
			Calls:    []livewireCall{{Path: "", Method: "deleteRecord", Params: []any{numericID}}},
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}
	return nil
}

// getRecordTTL returns the smallest valid TTL that is >= the requested TTL.
// Behavior when the TTL is unsupported is controlled by Provider.UnsupportedTTLisError.
func (p *Provider) getRecordTTL(ttl time.Duration) (time.Duration, error) {
	for _, validTTL := range ValidTTLs {
		if ttl < validTTL {
			if p.UnsupportedTTLisError {
				return 0, fmt.Errorf("unsupported TTL value: %s", ttl)
			}
			return validTTL, nil
		}
		if ttl == validTTL {
			return validTTL, nil
		}
	}
	if p.UnsupportedTTLisError {
		return 0, fmt.Errorf("unsupported TTL value: %s", ttl)
	}
	return ValidTTLs[len(ValidTTLs)-1], nil
}

// sameRecord compares two records by their RR representation (ignoring ProviderData).
func sameRecord(a, b libdns.Record) bool {
	ra, rb := a.RR(), b.RR()
	return ra.Name == rb.Name && ra.Type == rb.Type && ra.TTL == rb.TTL && ra.Data == rb.Data
}

// recordID returns the Neoserv-assigned numeric ID stored in ProviderData, or "" if absent.
func recordID(r libdns.Record) string {
	switch v := r.(type) {
	case libdns.Address:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.CNAME:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.MX:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.NS:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.TXT:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.SRV:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.CAA:
		s, _ := v.ProviderData.(string)
		return s
	case libdns.ServiceBinding:
		s, _ := v.ProviderData.(string)
		return s
	case ALIAS:
		s, _ := v.ProviderData.(string)
		return s
	case unknownRecord:
		s, _ := v.providerData.(string)
		return s
	}
	return ""
}

// RecordID returns the Neoserv-assigned record ID stored in ProviderData.
// Returns "" for records not fetched from this provider.
func RecordID(r libdns.Record) string {
	return recordID(r)
}
