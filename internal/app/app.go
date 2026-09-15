// Package app is the composition root. cmd/api/main.go and the struct CLI
// both call into this package so there is exactly one place that wires
// config, logging, services, and controllers together — no drift between
// what the server does and what the CLI does.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"struct-framework/internal/analytics"
	"struct-framework/internal/mvc/controllers"
	"struct-framework/internal/mvc/services"
	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/events"
	platformhttp "struct-framework/internal/platform/http"
	"struct-framework/internal/platform/i18n"
	"struct-framework/internal/platform/logging"
	"struct-framework/internal/platform/metrics"
	"struct-framework/internal/platform/procs"
	"struct-framework/internal/platform/security/authn"
	"struct-framework/internal/platform/security/webauthn"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/platform/store/postgres"
	"struct-framework/internal/platform/tracing"
	appcrypto "struct-framework/internal/support/crypto"
)

// App holds every long-lived dependency a running instance needs.
type App struct {
	Config        config.Config
	Logger        *slog.Logger
	Controllers   Controllers
	DB            store.Driver // nil when running on the in-memory store
	Broker        *events.Broker
	SigningKey    []byte
	EncryptionKey []byte
	Catalog       *i18n.Catalog
	MetricsReg    *metrics.Registry
	HTTPMetrics   *metrics.HTTPMetrics
	SpanExporter  tracing.SpanExporter
	Analytics     *analytics.Publisher
	StartTime     time.Time
}

// Build wires every dependency from cfg. It is the one function shared by
// cmd/api, `struct serve`, and `struct routes` (the latter never calls Run,
// so it never binds a socket).
func Build(cfg config.Config) (*App, error) {
	logger := logging.New(cfg)
	procs.SetGOMAXPROCS(logger)

	signingKey, err := resolveSigningKey(cfg)
	if err != nil {
		return nil, err
	}
	encryptionKey, err := resolveEncryptionKey(cfg)
	if err != nil {
		return nil, err
	}

	db, err := buildDB(cfg)
	if err != nil {
		return nil, err
	}

	catalog, err := i18n.LoadCatalog(cfg.DefaultLocale, cfg.SupportedLocales)
	if err != nil {
		return nil, fmt.Errorf("app: loading i18n catalog: %w", err)
	}
	controllers.SetTranslator(catalog)

	metricsReg := metrics.NewRegistry()
	metricsReg.RegisterRuntimeMetrics()
	httpMetrics := metrics.NewHTTPMetrics(metricsReg)

	var spanExporter tracing.SpanExporter = tracing.LogExporter{Logger: logger}
	if cfg.OTLPEndpoint != "" {
		spanExporter = tracing.NewOTLPExporter(cfg.OTLPEndpoint, cfg.ServiceName)
	}

	broker, err := events.NewBroker(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("app: initializing broker: %w", err)
	}

	analyticsPub := analytics.NewPublisher(
		analytics.LogSink{Logger: logger},
		logger,
		1000,
		analytics.WithDroppedEventsCounter(metricsReg.NewCounter("analytics_events_dropped_total", "Total dropped analytics events under backpressure")),
	)

	userSvc := BuildUserService(cfg, db)
	if inMemUser, ok := userSvc.(*services.InMemoryUserService); ok {
		inMemUser.SetEventPublisher(broker)
		inMemUser.SetAnalyticsPublisher(analyticsPub)
	}

	authSvc := BuildAuthService(cfg, db, userSvc, signingKey, encryptionKey)
	if inMemAuth, ok := authSvc.(*services.MemoryAuthService); ok {
		inMemAuth.SetEventPublisher(broker)
		inMemAuth.SetAnalyticsPublisher(analyticsPub)
	}

	startTime := time.Now().UTC()

	ctrls := Controllers{
		Config:     cfg,
		User:       controllers.NewUserController(userSvc),
		DB:         db, // nil is a valid Pinger value; ReadyzHandler checks for it
		Broker:     broker,
		MetricsReg: metricsReg,
		StartTime:  startTime,
	}
	if authSvc != nil {
		ctrls.Auth = controllers.NewAuthController(authSvc)
	}

	return &App{
		Config:        cfg,
		Logger:        logger,
		DB:            db,
		Broker:        broker,
		SigningKey:    signingKey,
		EncryptionKey: encryptionKey,
		Catalog:       catalog,
		MetricsReg:    metricsReg,
		HTTPMetrics:   httpMetrics,
		SpanExporter:  spanExporter,
		Analytics:     analyticsPub,
		Controllers:   ctrls,
		StartTime:     startTime,
	}, nil
}

// resolveSigningKey uses cfg.JWTSigningKey when set. Outside production,
// config.Load already permits it to be unset, so Build generates a
// process-lifetime ephemeral key instead — every access token issued
// becomes invalid on restart, which is expected and fine for local
// development; config.Load refuses to start in production without a real
// key explicitly configured, so this fallback is never reached there.
func resolveSigningKey(cfg config.Config) ([]byte, error) {
	if cfg.JWTSigningKey != "" {
		return []byte(cfg.JWTSigningKey), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("app: generating ephemeral JWT signing key: %w", err)
	}
	return key, nil
}

// resolveEncryptionKey mirrors resolveSigningKey, but always normalizes
// to exactly 32 bytes (AES-256's required key size) via
// appcrypto.DeriveKey, since operators may set ENCRYPTION_KEY to any
// string length. Every stored TOTP secret becomes permanently
// undecryptable if this key changes between restarts — outside
// production that's an accepted, documented trade-off for zero-config
// startup; config.Load refuses to start in production without a real
// key explicitly configured.
func resolveEncryptionKey(cfg config.Config) ([]byte, error) {
	if cfg.EncryptionKey != "" {
		return appcrypto.DeriveKey(cfg.EncryptionKey), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("app: generating ephemeral encryption key: %w", err)
	}
	return key, nil
}

// buildDB opens the configured store.Driver and pings it once so a bad
// connection string fails fast at startup rather than surfacing on the
// first request (framework guide §"Wired end to end"). It returns a nil
// Driver — not an error — when DBDriver is "memory".
func buildDB(cfg config.Config) (store.Driver, error) {
	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(cfg.DatabaseURL, cfg.DBMaxOpenConns)
		if err != nil {
			return nil, fmt.Errorf("app: opening postgres pool: %w", err)
		}
		return pingOrClose(pool, pool.Close)
	case "mysql":
		pool, err := mysql.Open(cfg.DatabaseURL, cfg.DBMaxOpenConns)
		if err != nil {
			return nil, fmt.Errorf("app: opening mysql pool: %w", err)
		}
		return pingOrClose(pool, pool.Close)
	default:
		return nil, nil
	}
}

// pingOrClose runs a bounded-timeout ping against db, closing it via
// closeFn and returning an error if the ping fails — shared by both
// dialect branches in buildDB so a bad connection string always fails
// fast, the same way, regardless of which database is configured.
func pingOrClose(db store.Driver, closeFn func() error) (store.Driver, error) {
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.Ping(pingCtx); err != nil {
		_ = closeFn()
		return nil, fmt.Errorf("app: database unreachable at startup: %w", err)
	}
	return db, nil
}

// BuildUserService selects the backing implementation for UserService,
// based on cfg.DBDriver — nothing above this function needs to know
// which one is active.
func BuildUserService(cfg config.Config, db store.Driver) services.UserService {
	switch cfg.DBDriver {
	case "postgres":
		repo := postgres.NewUserRepository(db)
		return services.NewPostgresUserService(repo)
	case "mysql":
		repo := mysql.NewUserRepository(db)
		return services.NewMySQLUserService(repo)
	default:
		return services.NewInMemoryUserService()
	}
}

// BuildAuthService selects the backing implementation for AuthService.
// When DBDriver is "postgres" or "mysql" with a database connection, it returns
// the dialect-backed service. When DBDriver is "memory" (or db is nil), it returns
// MemoryAuthService, enabling the full /v1/auth/* route suite out-of-the-box
// for zero-dependency local development and integration testing.
func BuildAuthService(cfg config.Config, db store.Driver, userSvc services.UserService, signingKey, encryptionKey []byte) controllers.AuthService {
	rpConfig := webauthn.Config{RPID: cfg.WebAuthnRPID, Origin: cfg.WebAuthnOrigin}
	if db != nil {
		switch cfg.DBDriver {
		case "postgres":
			users := postgres.NewUserRepository(db)
			tokens := postgres.NewRefreshTokenRepository(db)
			totpRepo := postgres.NewTOTPRepository(db)
			backupCodes := postgres.NewBackupCodeRepository(db)
			passkeys := postgres.NewWebAuthnCredentialRepository(db)
			return services.NewPostgresAuthService(users, tokens, totpRepo, backupCodes, passkeys, signingKey, encryptionKey, rpConfig)
		case "mysql":
			users := mysql.NewUserRepository(db)
			tokens := mysql.NewRefreshTokenRepository(db)
			totpRepo := mysql.NewTOTPRepository(db)
			backupCodes := mysql.NewBackupCodeRepository(db)
			passkeys := mysql.NewWebAuthnCredentialRepository(db)
			return services.NewMySQLAuthService(users, tokens, totpRepo, backupCodes, passkeys, signingKey, encryptionKey, rpConfig)
		}
	}

	if finder, ok := userSvc.(services.UserFinder); ok {
		return services.NewMemoryAuthService(finder, signingKey, encryptionKey, rpConfig)
	}
	return nil
}

// Routes returns the declarative route table (method, path) without
// binding a socket — used by `struct routes` so it stays instant/offline
// regardless of which DB_DRIVER is configured.
func (a *App) Routes() []platformhttp.Route {
	return Routes(a.Controllers)
}

// Run starts the HTTP server and blocks until SIGINT/SIGTERM, then drains
// in-flight requests within cfg.ShutdownTimeout before returning.
func (a *App) Run(ctx context.Context) error {
	mux := platformhttp.BuildMux(a.Routes())
	verifier := authn.NewVerifier(a.SigningKey)
	handler := platformhttp.BuildHandler(a.Config, a.Logger, mux, verifier, a.Catalog, a.HTTPMetrics, a.SpanExporter)
	srv := platformhttp.NewServer(a.Config, handler)

	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	if a.Analytics != nil {
		go a.Analytics.Run(workerCtx)
	}

	if a.Config.OutboxRelayEnabled && a.DB != nil {
		var outboxSource events.OutboxSource
		switch a.Config.DBDriver {
		case "postgres":
			outboxSource = postgres.NewOutboxPublisher(a.DB)
		case "mysql":
			outboxSource = mysql.NewOutboxPublisher(a.DB)
		}
		if outboxSource != nil {
			relay := events.NewRelay(outboxSource, events.LogSink{Logger: a.Logger}, a.Logger)
			go relay.Run(workerCtx, time.Second)
			a.Logger.Info("embedded outbox relay running")
		}
	}

	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("server starting", "port", a.Config.Port, "env", a.Config.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-stop:
		a.Logger.Info("shutdown signal received")
	case <-ctx.Done():
		a.Logger.Info("context cancelled")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.Config.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		a.Logger.Error("graceful shutdown failed", "error", err)
		return err
	}
	if a.DB != nil {
		if err := a.DB.Close(); err != nil {
			a.Logger.Error("closing database pool failed", "error", err)
		}
	}
	a.Logger.Info("shutdown complete")
	return nil
}
