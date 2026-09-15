package app

import (
	"net/http/pprof"
	"time"

	"struct-framework/internal/mvc/controllers"
	"struct-framework/internal/platform/config"
	platformhttp "struct-framework/internal/platform/http"
	"struct-framework/internal/platform/metrics"
)

// Controllers holds every controller and dependency a running instance wires up.
type Controllers struct {
	Config     config.Config
	User       *controllers.UserController
	Auth       *controllers.AuthController
	DB         platformhttp.Pinger
	Broker     platformhttp.Pinger
	MetricsReg *metrics.Registry
	StartTime  time.Time
}

// Routes is the single source of truth for this service's route table,
// shared by cmd/api (via BuildMux) and `struct routes` (which reads it
// without ever binding a socket).
func Routes(c Controllers) []platformhttp.Route {
	appName := c.Config.AppName
	if appName == "" {
		appName = "struct-framework"
	}
	appVersion := c.Config.AppVersion
	if appVersion == "" {
		appVersion = "1.0.0"
	}

	checks := map[string]platformhttp.Pinger{
		"database": c.DB,
	}
	if c.Broker != nil {
		checks["broker"] = c.Broker
	}

	routes := []platformhttp.Route{
		{Method: "GET", Path: "/healthz", Handler: platformhttp.DetailedHealthzHandler(appName, appVersion, c.StartTime)},
		{Method: "GET", Path: "/readyz", Handler: platformhttp.MultiReadyzHandler(checks)},
		{Method: "GET", Path: "/metrics", Handler: metrics.Handler(c.MetricsReg)},
		{Method: "POST", Path: "/v1/users", Handler: c.User.Create},
		{Method: "GET", Path: "/v1/users/{id}", Handler: c.User.Get},
	}

	if c.Config.PprofEnabled {
		routes = append(routes,
			platformhttp.Route{Method: "GET", Path: "/debug/pprof/", Handler: pprof.Index},
			platformhttp.Route{Method: "GET", Path: "/debug/pprof/cmdline", Handler: pprof.Cmdline},
			platformhttp.Route{Method: "GET", Path: "/debug/pprof/profile", Handler: pprof.Profile},
			platformhttp.Route{Method: "GET", Path: "/debug/pprof/symbol", Handler: pprof.Symbol},
			platformhttp.Route{Method: "POST", Path: "/debug/pprof/symbol", Handler: pprof.Symbol},
			platformhttp.Route{Method: "GET", Path: "/debug/pprof/trace", Handler: pprof.Trace},
		)
	}

	if c.Auth != nil {
		routes = append(routes,
			platformhttp.Route{Method: "POST", Path: "/v1/auth/login", Handler: c.Auth.Login},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/refresh", Handler: c.Auth.Refresh},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/logout", Handler: c.Auth.Logout},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/logout-all", Handler: c.Auth.LogoutAll}, // ✱
			platformhttp.Route{Method: "POST", Path: "/v1/auth/mfa/totp", Handler: c.Auth.VerifyMFATOTP},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/totp/enroll", Handler: c.Auth.EnrollTOTP},                             // ✱
			platformhttp.Route{Method: "POST", Path: "/v1/auth/totp/confirm", Handler: c.Auth.ConfirmTOTP},                           // ✱
			platformhttp.Route{Method: "DELETE", Path: "/v1/auth/totp", Handler: c.Auth.DisableTOTP},                                 // ✱
			platformhttp.Route{Method: "GET", Path: "/v1/auth/totp/backup-codes", Handler: c.Auth.BackupCodesRemaining},              // ✱
			platformhttp.Route{Method: "POST", Path: "/v1/auth/passkeys/register/begin", Handler: c.Auth.BeginPasskeyRegistration},   // ✱
			platformhttp.Route{Method: "POST", Path: "/v1/auth/passkeys/register/finish", Handler: c.Auth.FinishPasskeyRegistration}, // ✱
			platformhttp.Route{Method: "GET", Path: "/v1/auth/passkeys", Handler: c.Auth.ListPasskeys},                               // ✱
			platformhttp.Route{Method: "PATCH", Path: "/v1/auth/passkeys/{id}", Handler: c.Auth.RenamePasskey},                       // ✱
			platformhttp.Route{Method: "DELETE", Path: "/v1/auth/passkeys/{id}", Handler: c.Auth.DeletePasskey},                      // ✱
			platformhttp.Route{Method: "POST", Path: "/v1/auth/mfa/passkey/begin", Handler: c.Auth.BeginPasskeyMFA},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/mfa/passkey/finish", Handler: c.Auth.FinishPasskeyMFA},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/passkeys/login/begin", Handler: c.Auth.BeginPasskeyLogin},
			platformhttp.Route{Method: "POST", Path: "/v1/auth/passkeys/login/finish", Handler: c.Auth.FinishPasskeyLogin},
		)
	}
	return routes
}
