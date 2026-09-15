package tests

import (
	"context"
	"sync"
	"testing"

	"struct-framework/internal/analytics"
	"struct-framework/internal/mvc/services"
	"struct-framework/internal/platform/events"
	"struct-framework/internal/platform/security/webauthn"
)

type recordedEvent struct {
	Name        string
	AggregateID string
}

type testEventSubscriber struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (s *testEventSubscriber) handle(ctx context.Context, e events.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, recordedEvent{Name: e.Name, AggregateID: e.AggregateID})
	return nil
}

type testAnalyticsSink struct {
	mu     sync.Mutex
	events []analytics.Event
}

func (s *testAnalyticsSink) Send(ctx context.Context, e analytics.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

func TestMemoryAuthService_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	userSvc := services.NewInMemoryUserService()

	evPublisher := events.NewInMemoryPublisher()
	sub := &testEventSubscriber{}
	evPublisher.Subscribe("UserCreatedV1", sub.handle)
	evPublisher.Subscribe("UserLoggedInV1", sub.handle)

	anSink := &testAnalyticsSink{}
	anPublisher := analytics.NewPublisher(anSink, nil, 100)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	go anPublisher.Run(workerCtx)

	userSvc.SetEventPublisher(evPublisher)
	userSvc.SetAnalyticsPublisher(anPublisher)

	signingKey := []byte("01234567890123456789012345678901")
	encryptionKey := []byte("01234567890123456789012345678901")
	rpConfig := webauthn.Config{RPID: "localhost", Origin: "http://localhost:8080"}

	authSvc := services.NewMemoryAuthService(userSvc, signingKey, encryptionKey, rpConfig)
	authSvc.SetEventPublisher(evPublisher)
	authSvc.SetAnalyticsPublisher(anPublisher)

	// 1. Create User
	email := "alice@example.com"
	password := "SecurePassword123!"
	user, err := userSvc.CreateUser(ctx, email, password, "en")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if user.ID == "" {
		t.Fatalf("expected non-empty user ID")
	}

	// 2. Login with valid password
	access, refresh, ticket, err := authSvc.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatalf("expected access and refresh tokens, got access=%q refresh=%q", access, refresh)
	}
	if ticket != "" {
		t.Fatalf("expected no mfa ticket when TOTP is not enrolled")
	}

	// 3. Refresh Session
	newAccess, newRefresh, err := authSvc.RefreshSession(ctx, refresh)
	if err != nil {
		t.Fatalf("RefreshSession failed: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatalf("expected rotated access and refresh tokens")
	}

	// 4. Token Reuse Detection
	_, _, err = authSvc.RefreshSession(ctx, refresh) // Old token reused
	if err == nil {
		t.Fatalf("expected refresh token reuse to be rejected")
	}

	// 5. Subsequent refresh with rotated token must fail because whole family is revoked
	_, _, err = authSvc.RefreshSession(ctx, newRefresh)
	if err == nil {
		t.Fatalf("expected whole token family to be revoked after reuse")
	}

	// 6. Test Account Lockout
	wrongPassword := "WrongPassword!"
	for i := 0; i < 5; i++ {
		_, _, _, _ = authSvc.Login(ctx, email, wrongPassword)
	}
	_, _, _, err = authSvc.Login(ctx, email, password)
	if err == nil || err.Error() != "account is temporarily locked" {
		t.Fatalf("expected account locked error, got: %v", err)
	}
}

func TestMemoryAuthService_TOTP(t *testing.T) {
	ctx := context.Background()
	userSvc := services.NewInMemoryUserService()
	signingKey := []byte("01234567890123456789012345678901")
	encryptionKey := []byte("01234567890123456789012345678901")
	rpConfig := webauthn.Config{RPID: "localhost", Origin: "http://localhost:8080"}

	authSvc := services.NewMemoryAuthService(userSvc, signingKey, encryptionKey, rpConfig)

	user, err := userSvc.CreateUser(ctx, "bob@example.com", "Password123!", "en")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Enroll TOTP
	secret, uri, err := authSvc.EnrollTOTP(ctx, user.ID)
	if err != nil {
		t.Fatalf("EnrollTOTP failed: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatalf("expected non-empty secret and uri")
	}

	// Confirm with dummy code should fail
	_, err = authSvc.ConfirmTOTP(ctx, user.ID, "000000")
	if err == nil {
		t.Fatalf("expected invalid code to fail TOTP confirmation")
	}
}

func TestMemoryAuthService_DiscoverablePasskeyBegin(t *testing.T) {
	ctx := context.Background()
	userSvc := services.NewInMemoryUserService()
	signingKey := []byte("01234567890123456789012345678901")
	encryptionKey := []byte("01234567890123456789012345678901")
	rpConfig := webauthn.Config{RPID: "localhost", Origin: "http://localhost:8080"}

	authSvc := services.NewMemoryAuthService(userSvc, signingKey, encryptionKey, rpConfig)

	// Discoverable login begin with empty email
	ceremonyID, challenge, allowIDs, err := authSvc.BeginPasskeyLogin(ctx, "")
	if err != nil {
		t.Fatalf("BeginPasskeyLogin with empty email failed: %v", err)
	}
	if ceremonyID == "" {
		t.Fatalf("expected ceremonyID")
	}
	if len(challenge) == 0 {
		t.Fatalf("expected challenge")
	}
	if len(allowIDs) != 0 {
		t.Fatalf("expected empty allowIDs for discoverable passkey login, got %v", allowIDs)
	}
}
