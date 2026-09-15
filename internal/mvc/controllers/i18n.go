package controllers

import (
	"net/http"

	"struct-framework/internal/platform/http/middleware"
)

// Translator is the one method a localized response needs — declared
// here, not imported from internal/platform/i18n, matching this
// package's pattern elsewhere (AuthService, UserService) of depending
// only on method sets.
//
// Scope note (framework guide §9, Pass 5): only the small set of
// generic, framework-level messages below are localized in this pass —
// "invalid request body" and "authentication required". Business-logic
// error messages (login failures, TOTP/passkey errors, validation
// messages) are not yet routed through the catalog; see PLAN.md's Pass 5
// scope note for why that's a deliberate boundary, not an oversight.
type Translator interface {
	T(locale, key string, args ...any) string
}

// translator is package-level rather than a field on each controller
// struct so every handler shares one source of truth without every
// constructor needing a catalog parameter threaded through it — set
// once during startup via SetTranslator.
var translator Translator = noopTranslator{}

// SetTranslator wires the real i18n catalog in. Called once during
// internal/app.Build; never called at all (e.g. in a unit test that
// constructs a controller directly) leaves noopTranslator in place,
// which returns every key unchanged rather than panicking.
func SetTranslator(t Translator) {
	if t != nil {
		translator = t
	}
}

type noopTranslator struct{}

func (noopTranslator) T(locale, key string, args ...any) string { return key }

// translate resolves key using the request's negotiated locale
// (attached by middleware.Locale, which must run before routing for
// this to reflect anything other than the fallback).
func translate(r *http.Request, key string, args ...any) string {
	locale := middleware.LocaleFrom(r.Context())
	return translator.T(locale, key, args...)
}
