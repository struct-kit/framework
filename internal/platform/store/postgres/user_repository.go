package postgres

import (
	"context"
	"time"

	"struct-framework/internal/platform/store"
)

// UserRow is this package's own plain row shape — deliberately not
// internal/mvc/models.User. The framework guide's layering rule (§2)
// is that internal/platform must never import internal/mvc; a repository
// returning the domain model directly would violate that the moment it
// needed to construct one. Mapping UserRow <-> models.User happens one
// layer up, in internal/mvc/services, which is allowed to depend on both.
//
// LockedUntil is the zero time.Time when the account isn't locked —
// scanValue already maps a SQL NULL to the zero value for *time.Time, so
// no separate nullable-pointer type is needed here; callers check
// LockedUntil.IsZero() instead.
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

// UserRepository backs services.PostgresUserService. It takes store.Driver
// rather than *Pool so the exact same code runs whether it's given the
// pool directly or a store.Tx mid-transaction. Errors are returned
// as-is — a *PgError or store.ErrNoRows — with no apperr mapping here;
// apperr lives under internal/mvc, so mapping to it is a services-layer
// concern, not this package's.
type UserRepository struct {
	db store.Driver
}

func NewUserRepository(db store.Driver) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, row UserRow) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, locale, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		row.ID, row.Email, row.PasswordHash, row.Locale, row.CreatedAt, row.UpdatedAt,
	)
	return err
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (UserRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, locale, failed_login_attempts, locked_until, created_at, updated_at
		 FROM users WHERE id = $1`, id,
	)
	return scanUserRow(row)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (UserRow, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, locale, failed_login_attempts, locked_until, created_at, updated_at
		 FROM users WHERE email = $1`, email,
	)
	return scanUserRow(row)
}

// IncrementFailedAttempts increments and returns the new attempt count in
// one round trip, via Postgres's UPDATE ... RETURNING.
func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID string) (int, error) {
	row := r.db.QueryRow(ctx,
		`UPDATE users SET failed_login_attempts = failed_login_attempts + 1
		 WHERE id = $1 RETURNING failed_login_attempts`, userID)
	var attempts int
	err := row.Scan(&attempts)
	return attempts, err
}

// ResetLoginState clears the failed-attempt counter and any lock —
// called on every successful login.
func (r *UserRepository) ResetLoginState(ctx context.Context, userID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, userID)
	return err
}

// LockUntil locks the account until the given time.
func (r *UserRepository) LockUntil(ctx context.Context, userID string, until time.Time) error {
	_, err := r.db.Exec(ctx, `UPDATE users SET locked_until = $1 WHERE id = $2`, until, userID)
	return err
}

func scanUserRow(row store.Row) (UserRow, error) {
	var u UserRow
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Locale,
		&u.FailedLoginAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}
