package models

import "time"

// PasskeyInfo is what a passkey listing exposes — never the public key
// or any other internal credential detail.
type PasskeyInfo struct {
	CredentialID string
	Name         string
	CreatedAt    time.Time
}
