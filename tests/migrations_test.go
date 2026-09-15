package tests

import (
	"os"
	"path/filepath"
	"testing"

	"struct-framework/internal/platform/store"
)

func TestMigrations_LoadPairsAndSorting(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create two valid pairs
	m1Up := filepath.Join(tempDir, "20260101000000_create_users.up.sql")
	m1Down := filepath.Join(tempDir, "20260101000000_create_users.down.sql")
	m2Up := filepath.Join(tempDir, "20260102000000_create_orders.up.sql")
	m2Down := filepath.Join(tempDir, "20260102000000_create_orders.down.sql")

	if err := os.WriteFile(m1Up, []byte("CREATE TABLE users (id TEXT PRIMARY KEY);"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m1Down, []byte("DROP TABLE users;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m2Up, []byte("CREATE TABLE orders (id TEXT PRIMARY KEY);"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m2Down, []byte("DROP TABLE orders;"), 0644); err != nil {
		t.Fatal(err)
	}

	migrations, err := store.LoadMigrations(tempDir)
	if err != nil {
		t.Fatalf("unexpected error loading migrations: %v", err)
	}
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}
	if migrations[0].Version != "20260101000000" || migrations[0].Name != "create_users" {
		t.Errorf("unexpected first migration: %+v", migrations[0])
	}
	if migrations[1].Version != "20260102000000" || migrations[1].Name != "create_orders" {
		t.Errorf("unexpected second migration: %+v", migrations[1])
	}

	// 2. Unpaired migration must return an error
	orphanUp := filepath.Join(tempDir, "20260103000000_orphan.up.sql")
	if err := os.WriteFile(orphanUp, []byte("CREATE TABLE orphan;"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err = store.LoadMigrations(tempDir)
	if err == nil {
		t.Fatalf("expected error loading unpaired migration, got nil")
	}
}
