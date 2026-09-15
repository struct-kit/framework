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
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/support/crypto"
	"struct-framework/internal/support/validation"
)

// MySQLUserService implements the identical UserService interface
// InMemoryUserService and PostgresUserService do. As with
// PostgresUserService, the mysql.UserRow <-> models.User mapping and
// *mysql.MySQLError/store.ErrNoRows -> apperr translation happen here,
// since internal/platform/store/mysql must not import internal/mvc.
type MySQLUserService struct {
	repo *mysql.UserRepository
}

func NewMySQLUserService(repo *mysql.UserRepository) *MySQLUserService {
	return &MySQLUserService{repo: repo}
}

func (s *MySQLUserService) CreateUser(ctx context.Context, email, password, locale string) (models.User, error) {
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

	id, err := newMySQLUserID()
	if err != nil {
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to generate id", err)
	}

	now := time.Now().UTC()
	row := mysql.UserRow{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Locale:       locale,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.Create(ctx, row); err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.IsDuplicateEntry() {
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

func (s *MySQLUserService) GetUser(ctx context.Context, id string) (models.User, error) {
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

func newMySQLUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
