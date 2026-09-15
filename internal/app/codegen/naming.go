package codegen

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Pascal converts an arbitrary identifier ("order_item", "order-item",
// "orderItem", "OrderItem") into PascalCase ("OrderItem"), so `struct make`
// commands accept whatever casing a user types.
func Pascal(name string) string {
	fields := splitWords(name)
	var b strings.Builder
	for _, f := range fields {
		if f == "" {
			continue
		}
		r := []rune(f)
		b.WriteRune(unicode.ToUpper(r[0]))
		b.WriteString(strings.ToLower(string(r[1:])))
	}
	return b.String()
}

// Snake converts the same range of inputs into snake_case ("order_item"),
// used for generated file names.
func Snake(name string) string {
	fields := splitWords(name)
	lower := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			lower = append(lower, strings.ToLower(f))
		}
	}
	return strings.Join(lower, "_")
}

func splitWords(name string) []string {
	var words []string
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			words = append(words, current.String())
			current.Reset()
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && !unicode.IsUpper(runes[i-1]):
			flush()
			current.WriteRune(r)
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return words
}

// WriteGoFile formats source with go/format.Source and writes it to path,
// creating parent directories as needed. It refuses to overwrite an
// existing file — scaffolding must be explicit about replacing generated
// code, never silent about it.
func WriteGoFile(path, source string) error {
	formatted, err := format.Source([]byte(source))
	if err != nil {
		return fmt.Errorf("codegen: generated source for %s does not compile: %w", path, err)
	}
	return writeNewFile(path, formatted)
}

// WriteFile writes non-Go content (SQL migrations, etc.) with the same
// overwrite-refusal guarantee as WriteGoFile, but no gofmt pass.
func WriteFile(path, content string) error {
	return writeNewFile(path, []byte(content))
}

func writeNewFile(path string, content []byte) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("codegen: %s already exists — refusing to overwrite", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("codegen: checking %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("codegen: creating directory for %s: %w", path, err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return fmt.Errorf("codegen: writing %s: %w", path, err)
	}
	return nil
}
