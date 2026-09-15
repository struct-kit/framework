package mysql

import (
	"context"
	"time"

	"struct-framework/internal/platform/store"
)

type BackupCodeRow struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	CreatedAt time.Time
}

type BackupCodeRepository struct {
	db store.Driver
}

func NewBackupCodeRepository(db store.Driver) *BackupCodeRepository {
	return &BackupCodeRepository{db: db}
}

func (r *BackupCodeRepository) ReplaceAll(ctx context.Context, userID string, rows []BackupCodeRow) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_backup_codes WHERE user_id = ?`, userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, row := range rows {
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_backup_codes (id, user_id, code_hash, used, created_at) VALUES (?, ?, ?, ?, ?)`,
			row.ID, row.UserID, row.CodeHash, row.Used, row.CreatedAt,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// MarkUsed mirrors postgres.BackupCodeRepository.MarkUsed exactly — the
// single UPDATE's WHERE clause is the atomicity guarantee on this
// dialect too.
func (r *BackupCodeRepository) MarkUsed(ctx context.Context, userID, codeHash string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE user_backup_codes SET used = 1 WHERE user_id = ? AND code_hash = ? AND used = 0`,
		userID, codeHash,
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

func (r *BackupCodeRepository) CountUnused(ctx context.Context, userID string) (int, error) {
	row := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_backup_codes WHERE user_id = ? AND used = 0`, userID)
	var count int
	err := row.Scan(&count)
	return count, err
}

func (r *BackupCodeRepository) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM user_backup_codes WHERE user_id = ?`, userID)
	return err
}
