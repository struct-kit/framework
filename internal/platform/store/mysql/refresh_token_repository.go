package mysql

import (
	"context"
	"errors"
	"fmt"
	"time"

	"struct-framework/internal/platform/store"
)

// RefreshTokenRow mirrors postgres.RefreshTokenRow — see
// user_repository.go's UserRow doc comment for why this package can't
// share that type directly (internal/platform must not import
// internal/mvc, and neither dialect package imports the other).
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
	ErrTokenNotFound = errors.New("mysql: refresh token not found or expired")
	ErrTokenReused   = errors.New("mysql: refresh token reuse detected")
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
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.UserID, row.TokenHash, row.FamilyID, row.Revoked, row.CreatedAt, row.ExpiresAt,
	)
	return err
}

// Rotate mirrors postgres.RefreshTokenRepository.Rotate exactly — see
// that method's doc comment for the reuse-detection design. MySQL's
// `SELECT ... FOR UPDATE` inside a transaction provides the same row-lock
// guarantee Postgres's does.
func (r *RefreshTokenRepository) Rotate(ctx context.Context, tokenHash string, next RefreshTokenRow) (RefreshTokenRow, error) {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return RefreshTokenRow{}, fmt.Errorf("mysql: starting rotation transaction: %w", err)
	}

	existing, err := findRefreshTokenForUpdate(ctx, tx, tokenHash)
	if err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, err
	}

	if existing.Revoked {
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, existing.FamilyID); err != nil {
			_ = tx.Rollback()
			return RefreshTokenRow{}, fmt.Errorf("mysql: revoking reused token's family: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return RefreshTokenRow{}, fmt.Errorf("mysql: committing family revocation: %w", err)
		}
		return RefreshTokenRow{}, ErrTokenReused
	}

	if time.Now().UTC().After(existing.ExpiresAt) {
		_ = tx.Rollback()
		return RefreshTokenRow{}, ErrTokenNotFound
	}

	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, existing.ID); err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, fmt.Errorf("mysql: revoking rotated token: %w", err)
	}

	next.UserID = existing.UserID
	next.FamilyID = existing.FamilyID
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, revoked, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		next.ID, next.UserID, next.TokenHash, next.FamilyID, next.Revoked, next.CreatedAt, next.ExpiresAt,
	); err != nil {
		_ = tx.Rollback()
		return RefreshTokenRow{}, fmt.Errorf("mysql: inserting rotated token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return RefreshTokenRow{}, fmt.Errorf("mysql: committing rotation: %w", err)
	}
	return next, nil
}

func findRefreshTokenForUpdate(ctx context.Context, tx store.Tx, tokenHash string) (RefreshTokenRow, error) {
	row := tx.QueryRow(ctx,
		`SELECT id, user_id, family_id, revoked, created_at, expires_at
		 FROM refresh_tokens WHERE token_hash = ? FOR UPDATE`, tokenHash)
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

func (r *RefreshTokenRepository) FamilyIDByHash(ctx context.Context, tokenHash string) (string, error) {
	row := r.db.QueryRow(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	var familyID string
	if err := row.Scan(&familyID); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return "", ErrTokenNotFound
		}
		return "", err
	}
	return familyID, nil
}

func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := r.db.Exec(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, familyID)
	return err
}

func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}
