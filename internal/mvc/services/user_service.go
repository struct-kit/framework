package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"struct-framework/internal/analytics"
	"struct-framework/internal/mvc/apperr"
	"struct-framework/internal/mvc/models"
	"struct-framework/internal/platform/events"
	"struct-framework/internal/support/crypto"
	"struct-framework/internal/support/validation"
)

// UserService is the interface controllers.UserController depends on.
// InMemoryUserService satisfies it today; a future PostgresUserService and
// MySQLUserService (Pass 3) will satisfy it identically, so swapping the
// backing store never touches the controller layer.
type UserService interface {
	CreateUser(ctx context.Context, email, password, locale string) (models.User, error)
	GetUser(ctx context.Context, id string) (models.User, error)
}

type InMemoryUserService struct {
	mu         sync.RWMutex
	byID       map[string]models.User
	emailIndex map[string]string // lowercased email -> id
	events     events.Publisher
	analytics  *analytics.Publisher
}

func NewInMemoryUserService() *InMemoryUserService {
	return &InMemoryUserService{
		byID:       make(map[string]models.User),
		emailIndex: make(map[string]string),
	}
}

func (s *InMemoryUserService) SetEventPublisher(p events.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = p
}

func (s *InMemoryUserService) SetAnalyticsPublisher(p *analytics.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analytics = p
}

func (s *InMemoryUserService) CreateUser(ctx context.Context, email, password, locale string) (models.User, error) {
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

	s.mu.Lock()
	defer s.mu.Unlock()

	normalizedEmail := normalizeEmail(email)
	if _, exists := s.emailIndex[normalizedEmail]; exists {
		return models.User{}, apperr.Conflict("an account with this email already exists")
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to hash password", err)
	}

	id, err := newID()
	if err != nil {
		return models.User{}, apperr.Wrap(apperr.KindUnknown, "failed to generate id", err)
	}

	now := time.Now().UTC()
	u := models.User{
		ID:           id,
		Email:        email,
		PasswordHash: hash,
		Locale:       locale,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.byID[id] = u
	s.emailIndex[normalizedEmail] = id

	if s.events != nil {
		_ = s.events.Publish(ctx, events.Event{
			ID:          id,
			Name:        "UserCreatedV1",
			AggregateID: id,
			OccurredAt:  now,
			Payload:     map[string]any{"id": id, "email": email, "locale": locale},
		})
	}
	if s.analytics != nil {
		s.analytics.Track(analytics.Event{
			Name:      "UserRegistered",
			UserID:    id,
			Timestamp: now,
			Props:     map[string]any{"locale": locale},
		})
	}
	return u, nil
}

func (s *InMemoryUserService) GetUser(ctx context.Context, id string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.byID[id]
	if !ok {
		return models.User{}, apperr.NotFound("user not found")
	}
	return u, nil
}

func (s *InMemoryUserService) FindByEmail(ctx context.Context, email string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.emailIndex[normalizeEmail(email)]
	if !ok {
		return models.User{}, apperr.NotFound("user not found")
	}
	u, ok := s.byID[id]
	if !ok {
		return models.User{}, apperr.NotFound("user not found")
	}
	return u, nil
}

func normalizeEmail(email string) string {
	// Deliberately simple for the bootstrap slice: lowercase only. A
	// production mailbox-normalization pass (dots/plus-addressing per
	// provider) belongs in a dedicated helper once real providers matter.
	out := make([]byte, len(email))
	for i := 0; i < len(email); i++ {
		c := email[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
