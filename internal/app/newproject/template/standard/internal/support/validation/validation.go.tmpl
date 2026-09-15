// Package validation is a small, dependency-free field-error accumulator
// used in place of github.com/go-playground/validator, which this build
// environment cannot fetch. It covers the required/email/length rules the
// bootstrap slice needs; extend it rule-by-rule rather than reaching for
// reflection-based struct tags until the module proxy is available.
package validation

import (
	"fmt"
	"regexp"
	"strings"
)

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// Errors accumulates field -> message validation failures.
type Errors struct {
	fields map[string]string
}

func New() *Errors {
	return &Errors{fields: make(map[string]string)}
}

func (e *Errors) Add(field, message string) {
	if _, exists := e.fields[field]; !exists {
		e.fields[field] = message
	}
}

func (e *Errors) HasErrors() bool { return len(e.fields) > 0 }

func (e *Errors) Fields() map[string]string { return e.fields }

// Required fails if value is empty after trimming whitespace.
func (e *Errors) Required(field, value string) {
	if strings.TrimSpace(value) == "" {
		e.Add(field, fmt.Sprintf("%s is required", field))
	}
}

// Email fails if value is non-empty and does not look like an email
// address. Pair with Required if the field is mandatory.
func (e *Errors) Email(field, value string) {
	if value == "" {
		return
	}
	if !emailPattern.MatchString(value) {
		e.Add(field, fmt.Sprintf("%s must be a valid email address", field))
	}
}

// MinLength fails if value is shorter than min runes.
func (e *Errors) MinLength(field, value string, min int) {
	if len([]rune(value)) < min {
		e.Add(field, fmt.Sprintf("%s must be at least %d characters", field, min))
	}
}
