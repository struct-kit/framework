package mysql

import (
	"context"
	"time"

	"struct-framework/internal/platform/store"
)

// UserRow mirrors postgres.UserRow — see that type's doc comment for why
// this package can't share it directly, and for why LockedUntil is a
// plain time.Time (zero value means "not locked") rather than a nullable
// pointer type.
type UserRow struct {
	ID                  string
	Email               string
	PasswordHash        string
	Locale              string
	FailedLoginAttempts int
	LockedUntil         time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// UserRepository backs services.MySQLUserService. It takes store.Driver
// rather than *Pool so the exact same code runs whether it's given the
// pool directly or a store.Tx mid-transaction.
type UserRepository struct {
	db store.Driver
}

func NewUserRepository(db store.Driver) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, row UserRow) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, locale, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		row.ID, row.Email, row.PasswordHash, row.Locale, row.CreatedAt, row.UpdatedAt,
	)
	return err
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (UserRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, locale, failed_login_attempts, locked_until, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	)
	return scanUserRow(row)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (UserRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, locale, failed_login_attempts, locked_until, created_at, updated_at
		 FROM users WHERE email = ?`, email,
	)
	return scanUserRow(row)
}

// IncrementFailedAttempts increments the attempt count and reads it back
// — MySQL has no UPDATE ... RETURNING, so this is two round trips rather
// than Postgres's one. A minor, low-stakes race is possible between the
// UPDATE and the SELECT under concurrent failed logins on the same
// account; worst case is a slightly-off lockout count, not a security
// bypass (the lock itself is still applied once the threshold is
// crossed on any one of the racing reads).
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID string) (int, error) {
	if _, err := r.db.Exec(ctx,
		`UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`, userID); err != nil {
		return 0, err
	}
	row := r.db.QueryRow(ctx, `SELECT failed_login_attempts FROM users WHERE id = ?`, userID)
	var attempts int
	err := row.Scan(&attempts)
	return attempts, err
}

func (r *UserRepository) ResetLoginState(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`, userID)
	return err
}

func (r *UserRepository) LockUntil(ctx context.Context, userID string, until time.Time) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET locked_until = ? WHERE id = ?`, until, userID)
	return err
}

func scanUserRow(row store.Row) (UserRow, error) {
	var u UserRow
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Locale,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}
