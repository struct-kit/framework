package middleware

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"struct-framework/internal/platform/http/appctx"
)

const localeKey contextKey = "locale"

// LocaleResolver is the one method Locale needs — declared here, not
// imported from internal/platform/i18n, matching Auth's TokenVerifier
// pattern: this package never depends on a specific catalog
// implementation, just this one-method shape.
type LocaleResolver interface {
	IsSupported(locale string) bool
}

// Locale resolves the active locale per request, in priority order: an
// explicit ?locale= query parameter, then the highest-preference
// supported tag in the Accept-Language header, then defaultLocale. The
// resolved locale is attached to the request context for every
// downstream layer (framework guide §9.1).
func Locale(resolver LocaleResolver, defaultLocale string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			locale := resolveLocale(r, resolver, defaultLocale)
			ctx := context.WithValue(r.Context(), localeKey, locale)
			ctx = appctx.WithLocale(ctx, locale)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func resolveLocale(r *http.Request, resolver LocaleResolver, defaultLocale string) string {
	if q := r.URL.Query().Get("locale"); q != "" && resolver.IsSupported(q) {
		return q
	}
	for _, tag := range parseAcceptLanguage(r.Header.Get("Accept-Language")) {
		if resolver.IsSupported(tag) {
			return tag
		}
	}
	return defaultLocale
}

// parseAcceptLanguage returns the header's language tags ordered by
// preference (highest q-value first), with region subtags stripped
// (e.g. "en-US" -> "en") since this framework's catalogs are keyed by
// base language only.
func parseAcceptLanguage(header string) []string {
	type tagQ struct {
		tag string
		q   float64
	}
	var tags []tagQ
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Split(part, ";")
		tag := strings.TrimSpace(fields[0])
		if tag == "" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if v, ok := strings.CutPrefix(f, "q="); ok {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil {
					q = parsed
				}
			}
		}
		if idx := strings.Index(tag, "-"); idx != -1 {
			tag = tag[:idx]
		}
		tags = append(tags, tagQ{tag: tag, q: q})
	}
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].q > tags[j].q })

	result := make([]string, len(tags))
	for i, t := range tags {
		result[i] = t.tag
	}
	return result
}

// LocaleFrom retrieves the locale Locale attached to ctx, or "" if the
// middleware never ran (e.g. in a unit test).
func LocaleFrom(ctx context.Context) string {
	if loc := appctx.Locale(ctx); loc != "" {
		return loc
	}
	locale, _ := ctx.Value(localeKey).(string)
	return locale
}
