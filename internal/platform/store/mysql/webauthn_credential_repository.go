package mysql

import (
	"context"
	"errors"
	"time"

	"struct-framework/internal/platform/store"
)

// WebAuthnCredentialRow mirrors postgres.WebAuthnCredentialRow — see
// that type's doc comment for why the public key and credential ID are
// stored base64url-encoded rather than as raw bytes.
type WebAuthnCredentialRow struct {
	CredentialID string
	UserID       string
	PublicKeyX   string
	PublicKeyY   string
	SignCount    int64
	Name         string
	CreatedAt    time.Time
}

var ErrCredentialNotFound = errors.New("mysql: webauthn credential not found")

type WebAuthnCredentialRepository struct {
	db store.Driver
}

func NewWebAuthnCredentialRepository(db store.Driver) *WebAuthnCredentialRepository {
	return &WebAuthnCredentialRepository{db: db}
}

func (r *WebAuthnCredentialRepository) Create(ctx context.Context, row WebAuthnCredentialRow) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO webauthn_credentials (credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.CredentialID, row.UserID, row.PublicKeyX, row.PublicKeyY, row.SignCount, row.Name, row.CreatedAt,
	)
	return err
}

// FindByCredentialID is deliberately unscoped by user — see
// postgres.WebAuthnCredentialRepository.FindByCredentialID's doc comment
// for why that's correct here specifically.
func (r *WebAuthnCredentialRepository) FindByCredentialID(ctx context.Context, credentialID string) (WebAuthnCredentialRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at
		 FROM webauthn_credentials WHERE credential_id = ?`, credentialID)
	return scanWebAuthnCredentialRow(row)
}

func (r *WebAuthnCredentialRepository) ListForUser(ctx context.Context, userID string) ([]WebAuthnCredentialRow, error) {
	rows, err := r.db.Query(ctx,
		`SELECT credential_id, user_id, public_key_x, public_key_y, sign_count, name, created_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID)
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

func (r *WebAuthnCredentialRepository) UpdateSignCount(ctx context.Context, credentialID string, newCount int64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?`, newCount, credentialID)
	return err
}

// Rename mirrors postgres.WebAuthnCredentialRepository.Rename exactly —
// ownership-scoped by the WHERE clause, on this dialect too.
func (r *WebAuthnCredentialRepository) Rename(ctx context.Context, userID, credentialID, newName string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE webauthn_credentials SET name = ? WHERE credential_id = ? AND user_id = ?`,
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

func (r *WebAuthnCredentialRepository) Delete(ctx context.Context, userID, credentialID string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?`, credentialID, userID)
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
