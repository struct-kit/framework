package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Migration is one paired .up.sql/.down.sql file, keyed by its timestamp
// version prefix. Loading migration files is identical regardless of
// dialect; applying them (tracking schema_migrations, dirty-flag crash
// safety) is not, so each dialect package still has its own Migrator.
type Migration struct {
	Version string
	Name    string
	UpSQL   string
	DownSQL string
}

// MigrationStatus reports whether a specific migration has been applied.
type MigrationStatus struct {
	Version string
	Name    string
	Applied bool
}

// LoadMigrations reads dir for "<version>_<name>.up.sql" /
// "...down.sql" pairs and returns them sorted by version. An unpaired
// half (an .up.sql with no matching .down.sql, or vice versa) is an
// error — a migration that can't be rolled back is a trap waiting to
// spring during an incident.
func LoadMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: reading migrations directory %s: %w", dir, err)
	}

	type halfPair struct {
		up, down string
		hasUp    bool
		hasDown  bool
	}
	byKey := make(map[string]*halfPair) // key = "<version>_<name>"

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		var suffix string
		switch {
		case strings.HasSuffix(name, ".up.sql"):
			suffix = ".up.sql"
		case strings.HasSuffix(name, ".down.sql"):
			suffix = ".down.sql"
		default:
			continue
		}
		key := strings.TrimSuffix(name, suffix)
		p := byKey[key]
		if p == nil {
			p = &halfPair{}
			byKey[key] = p
		}
		full := filepath.Join(dir, name)
		if suffix == ".up.sql" {
			p.up, p.hasUp = full, true
		} else {
			p.down, p.hasDown = full, true
		}
	}

	var migrations []Migration
	for key, p := range byKey {
		if !p.hasUp || !p.hasDown {
			return nil, fmt.Errorf("store: migration %q is missing its %s half", key,
				map[bool]string{true: ".down.sql", false: ".up.sql"}[p.hasUp])
		}
		version, name, err := splitMigrationKey(key)
		if err != nil {
			return nil, err
		}
		upBytes, err := os.ReadFile(p.up)
		if err != nil {
			return nil, fmt.Errorf("store: reading %s: %w", p.up, err)
		}
		downBytes, err := os.ReadFile(p.down)
		if err != nil {
			return nil, fmt.Errorf("store: reading %s: %w", p.down, err)
		}
		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			UpSQL:   string(upBytes),
			DownSQL: string(downBytes),
		})
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

func splitMigrationKey(key string) (version, name string, err error) {
	parts := strings.SplitN(key, "_", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", fmt.Errorf("store: migration filename %q does not match <version>_<name>", key)
	}
	return parts[0], parts[1], nil
}
