package tests

import (
	"testing"

	"struct-framework/internal/platform/i18n"
)

func TestCatalog_LoadAndTranslate(t *testing.T) {
	cat, err := i18n.LoadCatalog("en", []string{"en", "es"})
	if err != nil {
		t.Fatalf("unexpected error loading catalog: %v", err)
	}

	if !cat.IsSupported("en") {
		t.Errorf("expected 'en' to be supported")
	}
	if !cat.IsSupported("es") {
		t.Errorf("expected 'es' to be supported")
	}
	if cat.IsSupported("de") {
		t.Errorf("expected 'de' not to be supported")
	}

	// Translation lookup
	msgEN := cat.T("en", "errors.invalid_request_body")
	if msgEN == "" || msgEN == "errors.invalid_request_body" {
		t.Errorf("expected translated message for errors.invalid_request_body, got %s", msgEN)
	}

	msgES := cat.T("es", "errors.invalid_request_body")
	if msgES == "" || msgES == msgEN {
		t.Errorf("expected Spanish translation for errors.invalid_request_body, got %s", msgES)
	}

	// Fallback lookup on unsupported/missing locale
	msgFallback := cat.T("ja", "errors.invalid_request_body")
	if msgFallback != msgEN {
		t.Errorf("expected fallback to default locale 'en', got %s", msgFallback)
	}
}

func TestCatalog_MissingFallback(t *testing.T) {
	_, err := i18n.LoadCatalog("non-existent-lang", []string{"non-existent-lang"})
	if err == nil {
		t.Fatal("expected error when fallback locale catalog is missing")
	}
}

func TestCatalog_MissingKeysCheck(t *testing.T) {
	cat, err := i18n.LoadCatalog("en", []string{"en", "es"})
	if err != nil {
		t.Fatalf("unexpected error loading catalog: %v", err)
	}

	missing := cat.MissingKeys()
	if len(missing["es"]) > 0 {
		t.Errorf("expected es to be complete relative to en, missing keys: %v", missing["es"])
	}
}
