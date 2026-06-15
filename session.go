package neoserv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// sessionCookieName is the Laravel session cookie set by moj.neoserv.si.
const sessionCookieName = "moj_session"

// cachedSession is the on-disk representation of a persisted login session.
type cachedSession struct {
	Cookie string `json:"cookie"`
}

// sessionCacheFile returns the path used to persist the session cookie. It
// honors Provider.SessionCachePath and otherwise falls back to a per-account
// file in the OS temp directory so different accounts do not collide.
func (p *Provider) sessionCacheFile() string {
	if p.SessionCachePath != "" {
		return p.SessionCachePath
	}
	sum := sha256.Sum256([]byte(p.Username))
	return filepath.Join(os.TempDir(), fmt.Sprintf("neoserv-session-%x.json", sum[:8]))
}

// sessionCookieValue returns the current moj_session cookie value, or "".
func (p *Provider) sessionCookieValue() string {
	for _, c := range p.client.Jar.Cookies(urlBaseP) {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	return ""
}

// setSessionCookie seeds the cookie jar with a moj_session value.
func (p *Provider) setSessionCookie(value string) {
	p.client.Jar.SetCookies(urlBaseP, []*http.Cookie{{Name: sessionCookieName, Value: value}})
}

// loadCachedSession reads a persisted session cookie from disk, or "" if there
// is none or it cannot be read.
func (p *Provider) loadCachedSession() string {
	data, err := os.ReadFile(p.sessionCacheFile())
	if err != nil {
		return ""
	}
	var cs cachedSession
	if err := json.Unmarshal(data, &cs); err != nil {
		return ""
	}
	return cs.Cookie
}

// saveCachedSession writes the current session cookie to disk with owner-only
// permissions, since it is a credential.
func (p *Provider) saveCachedSession() error {
	data, err := json.Marshal(cachedSession{Cookie: p.sessionCookieValue()})
	if err != nil {
		return err
	}
	return os.WriteFile(p.sessionCacheFile(), data, 0o600)
}

// sessionValid reports whether the current cookie jar holds a working session.
// It makes a cheap request that Laravel redirects to /login when the session is
// missing or expired, so it never touches the rate-limited login endpoint.
func (p *Provider) sessionValid(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlServices, nil)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && !strings.HasSuffix(resp.Request.URL.Path, "/login")
}

// reuseSession tries to authenticate without logging in, by reusing a session
// from the on-disk cache. It reports whether a valid session was established.
func (p *Provider) reuseSession(ctx context.Context) bool {
	if p.DisableSessionCache {
		return false
	}
	token := p.loadCachedSession()
	if token == "" {
		return false
	}
	p.setSessionCookie(token)
	return p.sessionValid(ctx)
}
