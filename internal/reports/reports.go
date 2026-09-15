// Package reports implements the framework guide's §8.5 reporting layer:
// scheduled or on-demand aggregate reports, built as a distinct read
// path.
//
// Production note: §8.5 specifies running reports against a replica or
// materialized view, never the primary write connection pool, to keep
// reporting load isolated from transactional traffic. This bootstrap
// framework has no replica-routing concept yet — SignupReport runs
// against whatever store.Driver it's given, which today is always the
// primary pool. Point it at a replica once one exists; nothing here
// would need to change beyond which Driver gets passed in.
package reports

import (
	"context"
	"fmt"

	"struct-framework/internal/platform/store"
)

// SignupCount is one day's aggregate signup count.
type SignupCount struct {
	Day   string
	Count int64
}

// SignupReport aggregates daily user signups over the last days days.
// dialect ("postgres" or "mysql") selects portable-enough SQL syntax —
// date-interval arithmetic isn't standardized across the two — while
// still executing through the generic store.Driver interface, so this
// package never imports either dialect package directly.
func SignupReport(ctx context.Context, db store.Driver, dialect string, days int) ([]SignupCount, error) {
	if days <= 0 {
		days = 30
	}

	var query string
	switch dialect {
	case "postgres":
		query = fmt.Sprintf(`
			SELECT to_char(created_at, 'YYYY-MM-DD') AS day, COUNT(*) AS signups
			FROM users
			WHERE created_at >= NOW() - INTERVAL '%d days'
			GROUP BY day
			ORDER BY day`, days)
	case "mysql":
		query = fmt.Sprintf(`
			SELECT DATE_FORMAT(created_at, '%%Y-%%m-%%d') AS day, COUNT(*) AS signups
			FROM users
			WHERE created_at >= NOW() - INTERVAL %d DAY
			GROUP BY day
			ORDER BY day`, days)
	default:
		return nil, fmt.Errorf("reports: unsupported dialect %q (want \"postgres\" or \"mysql\")", dialect)
	}

	rows, err := db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("reports: querying signup counts: %w", err)
	}
	defer rows.Close()

	var result []SignupCount
	for rows.Next() {
		var c SignupCount
		if err := rows.Scan(&c.Day, &c.Count); err != nil {
			return nil, fmt.Errorf("reports: scanning signup count: %w", err)
		}
		result = append(result, c)
	}
	return result, nil
}
