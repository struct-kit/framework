package tests

import (
	"strings"
	"testing"

	"struct-framework/internal/app/codegen"
)

func TestCodegen_RepositoryPostgresAndMySQL(t *testing.T) {
	module := "struct-framework"
	name := "Order"

	// 1. Postgres Repository
	pgPath, pgSource := codegen.RepositoryPostgres(module, name)
	if !strings.HasSuffix(pgPath, "internal/platform/store/postgres/order_repository.go") {
		t.Fatalf("unexpected pgPath: %s", pgPath)
	}
	if !strings.Contains(pgSource, "type OrderRow struct") {
		t.Fatalf("expected OrderRow in pgSource")
	}
	if !strings.Contains(pgSource, "type OrderRepository struct") {
		t.Fatalf("expected OrderRepository in pgSource")
	}
	if !strings.Contains(pgSource, "INSERT INTO order (id, created_at, updated_at) VALUES ($1, $2, $3)") {
		t.Fatalf("expected $1, $2, $3 placeholders in pgSource, got:\n%s", pgSource)
	}

	// 2. MySQL Repository
	myPath, mySource := codegen.RepositoryMySQL(module, name)
	if !strings.HasSuffix(myPath, "internal/platform/store/mysql/order_repository.go") {
		t.Fatalf("unexpected myPath: %s", myPath)
	}
	if !strings.Contains(mySource, "type OrderRow struct") {
		t.Fatalf("expected OrderRow in mySource")
	}
	if !strings.Contains(mySource, "type OrderRepository struct") {
		t.Fatalf("expected OrderRepository in mySource")
	}
	if !strings.Contains(mySource, "INSERT INTO order (id, created_at, updated_at) VALUES (?, ?, ?)") {
		t.Fatalf("expected ?, ?, ? placeholders in mySource, got:\n%s", mySource)
	}
}
