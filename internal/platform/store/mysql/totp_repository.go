package mysql

import (
	"context"
	"errors"
	"time"

	"struct-framework/internal/platform/store"
)

type TOTPRow struct {
	UserID          string
	SecretEncrypted string
	Confirmed       bool
	CreatedAt       time.Time
}

var ErrTOTPNotFound = errors.New("mysql: totp enrollment not found")

type TOTPRepository struct {
	db store.Driver
}

func NewTOTPRepository(db store.Driver) *TOTPRepository {
	return &TOTPRepository{db: db}
}

func (r *TOTPRepository) Upsert(ctx context.Context, row TOTPRow) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = ?`, row.UserID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO user_totp (user_id, secret_encrypted, confirmed, created_at) VALUES (?, ?, ?, ?)`,
		row.UserID, row.SecretEncrypted, row.Confirmed, row.CreatedAt,
	); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (r *TOTPRepository) Get(ctx context.Context, userID string) (TOTPRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT user_id, secret_encrypted, confirmed, created_at FROM user_totp WHERE user_id = ?`, userID)
	var t TOTPRow
	err := row.Scan(&t.UserID, &t.SecretEncrypted, &t.Confirmed, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return TOTPRow{}, ErrTOTPNotFound
		}
		return TOTPRow{}, err
	}
	return t, nil
}

func (r *TOTPRepository) Confirm(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `UPDATE user_totp SET confirmed = 1 WHERE user_id = ?`, userID)
	return err
}

func (r *TOTPRepository) Delete(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM user_totp WHERE user_id = ?`, userID)
	return err
}
