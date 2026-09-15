package cli

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/i18n"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/platform/store/postgres"
)

// newDoctorCmd implements framework guide §10.1's `struct doctor`.
// Pass 3 adds DATABASE_URL reachability; Pass 5 (i18n) adds locale-
// catalog completeness — this command is meant to grow with the
// framework, not be rewritten each time.
func newDoctorCmd() *Command {
	return &Command{
		Use:   "doctor",
		Short: "Check the local environment before you start developing",
		Run: func(args []string) error {
			ok := true

			check("Go runtime", runtime.Version(), true)

			cfg, err := config.Load()
			if err != nil {
				check("Configuration", err.Error(), false)
				return fmt.Errorf("doctor: one or more checks failed")
			}
			check("Configuration", fmt.Sprintf("loaded (env=%s, port=%d, db_driver=%s)", cfg.Env, cfg.Port, cfg.DBDriver), true)

			if cfg.IsProduction() {
				secretsOK := cfg.JWTSigningKey != "" && cfg.EncryptionKey != ""
				check("Production secrets (JWT_SIGNING_KEY, ENCRYPTION_KEY)", presence(secretsOK), secretsOK)
				if !secretsOK {
					ok = false
				}
			} else {
				check("Production secrets", "skipped (APP_ENV is not production)", true)
			}

			switch cfg.DBDriver {
			case "postgres", "mysql":
				if !checkDatabase(cfg) {
					ok = false
				}
			default:
				check("Database (DATABASE_URL)", "skipped (DB_DRIVER is \"memory\")", true)
			}

			if !checkI18n(cfg) {
				ok = false
			}

			if !ok {
				return fmt.Errorf("doctor: one or more checks failed")
			}
			return nil
		},
	}
}

// checkI18n loads the embedded catalog exactly as internal/app.Build
// does and reports any locale (among SUPPORTED_LOCALES) missing a
// translation for a key the fallback locale has — including a key
// present but left as an empty string, which `struct make locale`'s
// stub files start as (framework guide §9, Pass 5).
func checkI18n(cfg config.Config) bool {
	cat, err := i18n.LoadCatalog(cfg.DefaultLocale, cfg.SupportedLocales)
	if err != nil {
		check("i18n catalog", err.Error(), false)
		return false
	}

	missing := cat.MissingKeys()
	if len(missing) == 0 {
		check("i18n catalog", fmt.Sprintf("complete (%d locale(s): %v)", len(cat.SupportedLocales()), cat.SupportedLocales()), true)
		return true
	}

	ok := true
	for _, locale := range cat.SupportedLocales() {
		keys, incomplete := missing[locale]
		if !incomplete {
			continue
		}
		check(fmt.Sprintf("i18n catalog (%s)", locale), fmt.Sprintf("missing/untranslated: %v", keys), false)
		ok = false
	}
	return ok
}

func checkDatabase(cfg config.Config) bool {
	var db store.Driver
	var closeFn func() error

	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(cfg.DatabaseURL, 1)
		if err != nil {
			check("Database (DATABASE_URL)", err.Error(), false)
			return false
		}
		db, closeFn = pool, pool.Close
	case "mysql":
		pool, err := mysql.Open(cfg.DatabaseURL, 1)
		if err != nil {
			check("Database (DATABASE_URL)", err.Error(), false)
			return false
		}
		db, closeFn = pool, pool.Close
	default:
		check("Database (DATABASE_URL)", fmt.Sprintf("unknown DB_DRIVER %q", cfg.DBDriver), false)
		return false
	}
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.Ping(ctx); err != nil {
		check("Database (DATABASE_URL)", err.Error(), false)
		return false
	}
	check("Database (DATABASE_URL)", "reachable", true)
	return true
}

func check(name, detail string, ok bool) {
	mark := "OK  "
	if !ok {
		mark = "FAIL"
	}
	fmt.Fprintf(os.Stdout, "[%s] %-45s %s\n", mark, name, detail)
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "missing"
}
