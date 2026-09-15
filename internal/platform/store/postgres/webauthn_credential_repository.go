package postgres

import (
	"context"
	"errors"
	"time"

	"struct-framework/internal/platform/store"
)

// WebAuthnCredentialRow stores a passkey's public key as base64url-
// encoded text (both X and Y coordinates), not raw bytes — this
// package's text-based wire protocol parameter encoding sends []byte
// values as-is, and raw binary isn't guaranteed to be valid text in the
// database's encoding. Encoding to plain ASCII at this boundary avoids
// that risk entirely. CredentialID is base64url-encoded for the same
// reason (WebAuthn credential IDs are arbitrary binary, not text).
type WebAuthnCredentialRow struct {
	CredentialID string // base64url
	UserID       string
	PublicKeyX   string // base64url, 32 bytes decoded
	PublicKeyY   string // base64url, 32 bytes decoded
	SignCount    int64
	Name         string
	CreatedAt    time.Time
}

var ErrCredentialNotFound = errors.New("postgres: webauthn credential not found")

type WebAuthnCredentialRepository struct {
	db store.Driver
}

func NewWebAuthnCredentialRepository(db store.Driver) *WebAuthnCredentialRepository {
	return &WebAuthnCredentialRepository{db: db}
}

func (r *WebAuthnCredentialRepository) Create(ctx context.Context, row WebAuthnCredentialRow) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO webauthn_credentials (credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		row.CredentialID, row.UserID, row.PublicKeyX, row.PublicKeyY, row.SignCount, row.Name, row.CreatedAt,
	)
	return err
}

// FindByCredentialID looks up a credential by ID alone, with no
// ownership check — this is correct here specifically: during assertion
// verification we don't yet know who's logging in, and the signature
// check that follows (using the stored public key) is itself the proof
// of ownership. Every OTHER method below that mutates or exposes a
// credential is scoped to (userID, credentialID) — this is the one
// deliberate exception, not an oversight.
func (r *WebAuthnCredentialRepository) FindByCredentialID(ctx context.Context, credentialID string) (WebAuthnCredentialRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at
		 FROM webauthn_credentials WHERE credential_id = $1`, credentialID)
	return scanWebAuthnCredentialRow(row)
}

func (r *WebAuthnCredentialRepository) ListForUser(ctx context.Context, userID string) ([]WebAuthnCredentialRow, error) {
	rows, err := r.db.Query(ctx,
		`SELECT credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at
		 FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []WebAuthnCredentialRow
	for rows.Next() {
		row, err := scanWebAuthnCredentialRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, nil
}

// UpdateSignCount is unscoped by user for the same reason
// FindByCredentialID is — it's only ever called right after a
// signature has already been verified against this exact credential.
func (r *WebAuthnCredentialRepository) UpdateSignCount(ctx context.Context, credentialID string, newCount int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = $1 WHERE credential_id = $2`, newCount, credentialID)
	return err
}

// Rename is ownership-scoped: the WHERE clause requires both the
// credential ID and the caller's user ID to match, so a caller can never
// rename another user's passkey by guessing or observing its credential
// ID. It reports whether a row was actually affected, so the service
// layer can tell "not found or not yours" apart from an unrelated error.
func (r *WebAuthnCredentialRepository) Rename(ctx context.Context, userID, credentialID, newName string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE webauthn_credentials SET name = $1 WHERE credential_id = $2 AND user_id = $3`,
		newName, credentialID, userID,
	)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Delete is ownership-scoped for the same reason Rename is.
func (r *WebAuthnCredentialRepository) Delete(ctx context.Context, userID, credentialID string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE credential_id = $1 AND user_id = $2`, credentialID, userID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func scanWebAuthnCredentialRow(row store.Row) (WebAuthnCredentialRow, error) {
	var c WebAuthnCredentialRow
	err := row.Scan(&c.CredentialID, &c.UserID, &c.PublicKeyX, &c.PublicKeyY, &c.SignCount, &c.Name, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return WebAuthnCredentialRow{}, ErrCredentialNotFound
		}
		return WebAuthnCredentialRow{}, err
	}
	return c, nil
}
