package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"struct-framework/internal/mvc/apperr"
	"struct-framework/internal/mvc/models"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/postgres"
	"struct-framework/internal/support/crypto"
	"struct-framework/internal/support/validation"
)

// PostgresUserService implements the identical UserService interface
// InMemoryUserService does — internal/app.BuildUserService is the only
// place that decides which one is actually wired in. This is also where
// postgres.UserRow <-> models.User mapping and *postgres.PgError/
// store.ErrNoRows -> apperr translation happen — internal/platform/store
// itself must not import internal/mvc (framework guide §2), so this
// layer is where the two worlds meet.
type PostgresUserService struct {
	repo *postgres.UserRepository
}

func NewPostgresUserService(repo *postgres.UserRepository) *PostgresUserService {
	return &PostgresUserService{repo: repo}
}

func (s *PostgresUserService) CreateUser(ctx context.Context, email, password, locale string) (models.User, error) {
	errs := validation.New()
	errs.Required("email", email)
	errs.Email("email", email)
	errs.Required("password", password)
	errs.MinLength("password", password, 8)
	if errs.HasErrors() {
		return models.User{}, apperr.Validation(errs.Fields())
	}
	if locale == "" {
		locale = "en"
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to hash password", err)
	}

	id, err := newUserID()
	if err != nil {
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to generate id", err)
	}

	now := time.Now().UTC()
	row := postgres.UserRow{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Locale:       locale,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, row); err != nil {
		var pgErr *postgres.PgError
		if errors.As(err, &pgErr) && pgErr.IsUniqueViolation() {
			return models.User{}, apperr.Conflict("an account with this email already exists")
		}
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to create user", err)
	}

	return models.User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Locale:       locale,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (s *PostgresUserService) GetUser(ctx context.Context, id string) (models.User, error) {
	row, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return models.User{}, apperr.NotFound("user not found")
		}
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to look up user", err)
	}
	return models.User{
		ID:           row.ID,
		Email:        row.Email,
		PasswordHash: row.PasswordHash,
		Locale:       row.Locale,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}, nil
}

func newUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
