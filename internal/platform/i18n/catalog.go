// Package i18n implements the framework guide's §9 message-catalog
// layer: embedded, locale-keyed message templates with a documented,
// startup-time-checked fallback.
//
// Deviation from the framework guide's project layout: §2's top-level
// directory diagram shows `locales/` at the project root. That's not
// achievable with a real //go:embed directive — embed patterns cannot
// reference a parent directory (no ".." components), so a directive
// living in this package can only embed a subtree of its own directory.
// locales/ therefore lives at internal/platform/i18n/locales/ instead —
// still one place, still embedded into the binary, just nested under the
// package that owns it rather than at the repository root.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed locales/*.json
var localesFS embed.FS

// Catalog holds every embedded locale's messages, plus which locales are
// actually offered at runtime (supported) — a subset of what's embedded,
// controlled by SUPPORTED_LOCALES, so an operator can ship translation
// files without turning every one of them on immediately.
type Catalog struct {
	messages  map[string]map[string]string // locale -> key -> template
	fallback  string
	supported map[string]bool
}

// LoadCatalog reads every embedded locales/*.json file, then validates
// that fallback and every locale in allowed actually has one — a
// SUPPORTED_LOCALES entry with no matching catalog file is a startup-time
// configuration error, not a silent no-op, matching this framework's
// fail-fast conventions elsewhere (JWT signing key, database
// connectivity, migration state).
func LoadCatalog(fallback string, allowed []string) (*Catalog, error) {
	entries, err := localesFS.ReadDir("locales")
	if err != nil {
		return nil, fmt.Errorf("i18n: reading embedded locales: %w", err)
	}

	messages := make(map[string]map[string]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		locale := strings.TrimSuffix(e.Name(), ".json")
		data, err := localesFS.ReadFile("locales/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("i18n: reading %s: %w", e.Name(), err)
		}
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("i18n: parsing %s: %w", e.Name(), err)
		}
		messages[locale] = m
	}

	if _, ok := messages[fallback]; !ok {
		return nil, fmt.Errorf("i18n: fallback locale %q has no embedded catalog file", fallback)
	}

	supported := map[string]bool{fallback: true} // the fallback is always supported
	for _, l := range allowed {
		if _, ok := messages[l]; !ok {
			return nil, fmt.Errorf("i18n: SUPPORTED_LOCALES lists %q, but no embedded catalog exists for it", l)
		}
		supported[l] = true
	}

	return &Catalog{messages: messages, fallback: fallback, supported: supported}, nil
}

// T resolves key in locale, falling back to the fallback locale, then to
// the key itself if the translation is truly missing everywhere — a
// missing key becomes a visible, debuggable string in the response
// rather than an empty one.
func (c *Catalog) T(locale, key string, args ...any) string {
	tmpl, ok := c.lookup(locale, key)
	if !ok {
		return key
	}
	if len(args) == 0 {
		return tmpl
	}
	return fmt.Sprintf(tmpl, args...)
}

func (c *Catalog) lookup(locale, key string) (string, bool) {
	if msgs, ok := c.messages[locale]; ok {
		if v, ok := msgs[key]; ok && v != "" {
			return v, true
		}
	}
	if msgs, ok := c.messages[c.fallback]; ok {
		if v, ok := msgs[key]; ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// IsSupported reports whether locale is one SUPPORTED_LOCALES (or the
// fallback) actually offers — the one method middleware.Locale needs.
func (c *Catalog) IsSupported(locale string) bool {
	return c.supported[locale]
}

// SupportedLocales returns every currently-offered locale, sorted.
func (c *Catalog) SupportedLocales() []string {
	locales := make([]string, 0, len(c.supported))
	for l := range c.supported {
		locales = append(locales, l)
	}
	sort.Strings(locales)
	return locales
}

// MissingKeys reports, for each supported non-fallback locale, which keys
// the fallback locale has that it doesn't — or that it has only as an
// empty string, which `struct make locale`'s stub files start as and
// which is exactly "not yet translated" in practice, not a valid
// translation. Used by `struct doctor`'s catalog-completeness check.
func (c *Catalog) MissingKeys() map[string][]string {
	fallbackKeys := c.messages[c.fallback]
	missing := make(map[string][]string)
	for locale := range c.supported {
		if locale == c.fallback {
			continue
		}
		msgs := c.messages[locale]
		var miss []string
		for k := range fallbackKeys {
			if v, ok := msgs[k]; !ok || v == "" {
				miss = append(miss, k)
			}
		}
		if len(miss) > 0 {
			sort.Strings(miss)
			missing[locale] = miss
		}
	}
	return missing
}
