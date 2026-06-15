package neoserv

import "testing"

// rateLimitPageHTML is a representative fragment of the login page shown when the
// account is temporarily blocked from logging in.
const rateLimitPageHTML = `<div class="alert alert-danger" role="alert">
<h5 class="mb-1 fw-bold text-danger">Neuspešna prijava</h5>
<span class="text-danger">Dosegli ste maksimalno število poskusov prijave. Prosimo, poskusite ponovno čez eno uro.</span>
</div>`

func TestIsLoginRateLimited(t *testing.T) {
	if !isLoginRateLimited(rateLimitPageHTML) {
		t.Fatal("expected rate-limit page to be detected")
	}
	// A normal login page (or a bad-credentials page) must not be flagged.
	if isLoginRateLimited(`<form action="/login"><input name="email"></form>`) {
		t.Fatal("false positive on a normal login page")
	}
}
