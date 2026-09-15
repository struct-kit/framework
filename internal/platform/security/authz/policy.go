// Package authz is the authorization layer (framework guide §6.4/§7.4):
// RBAC via typed permission structs, checked here — never inline
// `if user.Role == "admin"` scattered across controllers.
package authz

import "context"

// Decision is deliberately zero-valued to Deny, so a Policy that forgets to
// set a return value denies by default rather than silently allowing.
type Decision int

const (
	Deny Decision = iota
	Allow
)

// Subject is the caller a Policy evaluates against. Roles is intentionally
// a slice, not a single string, since a caller may hold more than one role.
type Subject struct {
	UserID string
	Roles  []string
}

// Policy is the contract every generated policy (`struct make policy NAME`)
// implements. Evaluate must return Deny for any case it does not
// explicitly recognize.
type Policy interface {
	Evaluate(ctx context.Context, subject Subject, action, resource string) Decision
}

// HasRole is a small helper most policies will use.
func HasRole(s Subject, role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}
