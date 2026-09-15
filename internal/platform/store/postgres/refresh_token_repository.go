package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"struct-framework/internal/platform/store"
)

// RefreshTokenRow is this package's own plain row shape — see
// user_repository.go's UserRow doc comment for why (internal/platform
// must not import internal/mvc).
type RefreshTokenRow struct {
	ID        string
	UserID    string
	TokenHash string
	FamilyID  string
	Revoked   bool
	CreatedAt time.Time
	ExpiresAt time.Time
}

var (
	ErrTokenNotFound = errors.New("postgres: refresh token not found or expired")
	ErrTokenReused   = errors.New("postgres: refresh token reuse detected")
)

type RefreshTokenRepository struct {
	db store.Driver
}

func NewRefreshTokenRepository(db store.Driver) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, row RefreshTokenRow) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, revoked, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		row.ID, row.UserID, row.TokenHash, row.FamilyID, row.Revoked, row.CreatedAt, row.ExpiresAt,
	)
	return err
}

// Rotate is the one operation this table exists for: it looks up the
// token matching tokenHash, and — if it's valid and unexpired — revokes
// it and inserts next in the same family, atomically, inside a
// transaction with a row lock (SELECT ... FOR UPDATE) so two concurrent
// refresh attempts on the same token can't both succeed.
//
// If the matched token is already revoked, that's a theft signal — it
// means someone presented a refresh token that had already been rotated
// away, which should only ever happen once per token. Rotate responds by
// revoking every token in that family (not just the one presented) and
// returning ErrTokenReused, so a stolen-and-reused token invalidates the
// legitimate rotated successor too.
func (r *RefreshTokenRepository) Rotate(ctx context.Context, tokenHash string, next RefreshTokenRow) (RefreshTokenRow, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return RefreshTokenRow{}, fmt.Errorf("postgres: starting rotation transaction: %w", err)
	}

	existing, err := findRefreshTokenForUpdate(ctx, tx, tokenHash)
	if err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, err
	}

	if existing.Revoked {
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE family_id = $1`, existing.FamilyID); err != nil {
			_ = tx.Rollback()
			return RefreshTokenRow{}, fmt.Errorf("postgres: revoking reused token's family: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return RefreshTokenRow{}, fmt.Errorf("postgres: committing family revocation: %w", err)
		}
		return RefreshTokenRow{}, ErrTokenReused
	}

	if time.Now().UTC().After(existing.ExpiresAt) {
		_ = tx.Rollback()
		return RefreshTokenRow{}, ErrTokenNotFound
	}

	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE id = $1`, existing.ID); err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, fmt.Errorf("postgres: revoking rotated token: %w", err)
	}

	next.UserID = existing.UserID
	next.FamilyID = existing.FamilyID
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, revoked, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		next.ID, next.UserID, next.TokenHash, next.FamilyID, next.Revoked, next.CreatedAt, next.ExpiresAt,
	); err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, fmt.Errorf("postgres: inserting rotated token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RefreshTokenRow{}, fmt.Errorf("postgres: committing rotation: %w", err)
	}
	return next, nil
}

func findRefreshTokenForUpdate(ctx context.Context, tx store.Tx, tokenHash string) (RefreshTokenRow, error) {
	row := tx.QueryRow(ctx,
		`SELECT id, user_id, family_id, revoked, created_at, expires_at
		 FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash)
	var t RefreshTokenRow
	err := row.Scan(&t.ID, &t.UserID, &t.FamilyID, &t.Revoked, &t.CreatedAt, &t.ExpiresAt)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return RefreshTokenRow{}, ErrTokenNotFound
		}
		return RefreshTokenRow{}, err
	}
	t.TokenHash = tokenHash
	return t, nil
}

// FamilyIDByHash looks up which family a token hash belongs to, valid or
// already revoked — Logout uses this to revoke the right family without
// the caller needing to track it separately.
func (r *RefreshTokenRepository) FamilyIDByHash(ctx context.Context, tokenHash string) (string, error) {
	row := r.db.QueryRow(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	var familyID string
	if err := row.Scan(&familyID); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return "", ErrTokenNotFound
		}
		return "", err
	}
	return familyID, nil
}

// RevokeFamily revokes every token descended from one login — Logout
// ends just that session, not every session the user has.
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := r.db.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE family_id = $1`, familyID)
	return err
}

// RevokeAllForUser revokes every refresh token belonging to userID,
// across every family — used by LogoutAll.
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1`, userID)
	return err
}
