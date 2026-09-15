package codegen

import "fmt"

// Model generates a plain domain struct under internal/mvc/models.
func Model(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/mvc/models/%s.go", snake)
	source = fmt.Sprintf(`package models

import "time"

// %s is a plain domain struct — no framework or SQL-dialect coupling.
// Add validation tags here as fields are added (framework guide §3.1).
type %s struct {
	ID        string
	CreatedAt time.Time
	UpdatedAt time.Time
}
`, pascal, pascal)
	return path, source
}

// DTO generates a response view type under internal/mvc/views that never
// leaks internal model fields (framework guide §3.3).
func DTO(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/mvc/views/%s_view.go", snake)
	source = fmt.Sprintf(`package views

import (
	"time"

	"%s/internal/mvc/models"
)

// %sResponse is the only shape of a %s ever sent over the wire.
type %sResponse struct {
	ID        string %sjson:"id"%s
	CreatedAt string %sjson:"created_at"%s
}

func From%s(m models.%s) %sResponse {
	return %sResponse{
		ID:        m.ID,
		CreatedAt: m.CreatedAt.Format(time.RFC3339),
	}
}
`, modulePath, pascal, pascal, pascal, "`", "`", "`", "`", pascal, pascal, pascal, pascal)
	return path, source
}

// Enum generates a typed string enum with JSON (un)marshaling and a Valid
// method, under internal/mvc/models.
func Enum(modulePath, name string, values []string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/mvc/models/%s_enum.go", snake)

	var consts, caseList string
	for _, v := range values {
		vp := Pascal(v)
		consts += fmt.Sprintf("\t%s%s %s = %q\n", pascal, vp, pascal, v)
		caseList += fmt.Sprintf("\tcase %s%s:\n\t\treturn true\n", pascal, vp)
	}

	source = fmt.Sprintf(`package models

import (
	"encoding/json"
	"fmt"
)

// %s is a typed string enum. Extend the const block and Valid together —
// never accept a %s value that Valid does not recognize.
type %s string

const (
%s)

func (e %s) String() string { return string(e) }

func (e %s) Valid() bool {
	switch e {
%s	default:
		return false
	}
}

func (e %s) MarshalJSON() ([]byte, error) {
	if !e.Valid() {
		return nil, fmt.Errorf("%s: invalid value %%q", string(e))
	}
	return json.Marshal(string(e))
}

func (e *%s) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	candidate := %s(s)
	if !candidate.Valid() {
		return fmt.Errorf("%s: invalid value %%q", s)
	}
	*e = candidate
	return nil
}
`, pascal, pascal, pascal, consts, pascal, pascal, caseList, pascal, pascal, pascal, pascal, pascal)
	return path, source
}

// Service generates a service interface plus an in-memory implementation,
// following the same pattern as services.UserService/InMemoryUserService
// so a future store-backed implementation (Pass 3) can satisfy the same
// interface without touching the controller layer.
func Service(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/mvc/services/%s_service.go", snake)
	source = fmt.Sprintf(`package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"%s/internal/mvc/apperr"
	"%s/internal/mvc/models"
)

// %sService is the interface controllers.%sController depends on.
// InMemory%sService satisfies it today; a future store-backed
// implementation (Pass 3) satisfies it identically.
type %sService interface {
	Create%s(ctx context.Context) (models.%s, error)
	Get%s(ctx context.Context, id string) (models.%s, error)
}

type InMemory%sService struct {
	mu   sync.RWMutex
	byID map[string]models.%s
}

func NewInMemory%sService() *InMemory%sService {
	return &InMemory%sService{byID: make(map[string]models.%s)}
}

func (s *InMemory%sService) Create%s(ctx context.Context) (models.%s, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := new%sID()
	if err != nil {
		return models.%s{}, apperr.Wrap(apperr.KindUnknown, "failed to generate id", err)
	}

	now := time.Now().UTC()
	m := models.%s{ID: id, CreatedAt: now, UpdatedAt: now}
	s.byID[id] = m
	return m, nil
}

func (s *InMemory%sService) Get%s(ctx context.Context, id string) (models.%s, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.byID[id]
	if !ok {
		return models.%s{}, apperr.NotFound("%s not found")
	}
	return m, nil
}

func new%sID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate id: %%w", err)
	}
	return hex.EncodeToString(b), nil
}
`, modulePath, modulePath,
		pascal, pascal, pascal,
		pascal, pascal, pascal, pascal, pascal,
		pascal, pascal,
		pascal, pascal, pascal, pascal,
		pascal, pascal, pascal, pascal, pascal, pascal,
		pascal, pascal, pascal,
		pascal, snake,
		pascal)
	return path, source
}

// Controller generates HTTP handlers for the same entity, depending only
// on a locally-declared service interface (never a concrete type),
// mirroring internal/mvc/controllers/user_controller.go.
func Controller(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/mvc/controllers/%s_controller.go", snake)
	source = fmt.Sprintf(`package controllers

import (
	"context"
	"net/http"

	"%s/internal/mvc/models"
	"%s/internal/mvc/views"
)

type %sService interface {
	Create%s(ctx context.Context) (models.%s, error)
	Get%s(ctx context.Context, id string) (models.%s, error)
}

type %sController struct {
	svc %sService
}

func New%sController(svc %sService) *%sController {
	return &%sController{svc: svc}
}

func (c *%sController) Create(w http.ResponseWriter, r *http.Request) {
	m, err := c.svc.Create%s(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, views.From%s(m))
}

func (c *%sController) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id", nil)
		return
	}
	m, err := c.svc.Get%s(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views.From%s(m))
}

// This file shares writeServiceError/writeJSON/writeError with
// user_controller.go in this same package — it assumes that file (from
// the standard/full project templates) is present.
`, modulePath, modulePath,
		pascal, pascal, pascal, pascal, pascal,
		pascal, pascal,
		pascal, pascal, pascal, pascal,
		pascal, pascal, pascal,
		pascal, pascal, pascal)
	return path, source
}

// RepositoryPostgres generates a store.Driver-backed repository for PostgreSQL
// under internal/platform/store/postgres, returning a package-local row shape
// to maintain the strict layering rule (internal/platform never imports internal/mvc).
func RepositoryPostgres(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/platform/store/postgres/%s_repository.go", snake)
	source = fmt.Sprintf(`package postgres

import (
	"context"
	"time"

	"struct-framework/internal/platform/store"
)

// %sRow is this package's own plain row shape — deliberately not
// internal/mvc/models.%s to preserve the layering rule (§2).
type %sRow struct {
	ID        string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// %sRepository backs services.Postgres%sService. It takes store.Driver
// rather than *Pool so the exact same code runs whether it's given the
// pool directly or a store.Tx mid-transaction.
type %sRepository struct {
	db store.Driver
}

func New%sRepository(db store.Driver) *%sRepository {
	return &%sRepository{db: db}
}

func (r *%sRepository) Create(ctx context.Context, row %sRow) error {
	_, err := r.db.Exec(ctx,
		"INSERT INTO %s (id, created_at, updated_at) VALUES ($1, $2, $3)",
		row.ID, row.CreatedAt, row.UpdatedAt,
	)
	return err
}

func (r *%sRepository) FindByID(ctx context.Context, id string) (%sRow, error) {
	row := r.db.QueryRow(ctx,
		"SELECT id, created_at, updated_at FROM %s WHERE id = $1", id,
	)
	return scan%sRow(row)
}

func scan%sRow(row store.Row) (%sRow, error) {
	var out %sRow
	if err := row.Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return %sRow{}, err
	}
	return out, nil
}
`, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, snake, pascal, pascal, snake, pascal, pascal, pascal, pascal, pascal)
	return path, source
}

// RepositoryMySQL generates a store.Driver-backed repository for MySQL
// under internal/platform/store/mysql, using ? parameter markers and
// COM_STMT_PREPARE/EXECUTE via store.Driver.
func RepositoryMySQL(modulePath, name string) (path, source string) {
	pascal := Pascal(name)
	snake := Snake(name)
	path = fmt.Sprintf("internal/platform/store/mysql/%s_repository.go", snake)
	source = fmt.Sprintf(`package mysql

import (
	"context"
	"time"

	"struct-framework/internal/platform/store"
)

// %sRow is this package's own plain row shape — deliberately not
// internal/mvc/models.%s to preserve the layering rule (§2).
type %sRow struct {
	ID        string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// %sRepository backs services.MySQL%sService. It takes store.Driver
// rather than *Pool so the exact same code runs whether it's given the
// pool directly or a store.Tx mid-transaction.
type %sRepository struct {
	db store.Driver
}

func New%sRepository(db store.Driver) *%sRepository {
	return &%sRepository{db: db}
}

func (r *%sRepository) Create(ctx context.Context, row %sRow) error {
	_, err := r.db.Exec(ctx,
		"INSERT INTO %s (id, created_at, updated_at) VALUES (?, ?, ?)",
		row.ID, row.CreatedAt, row.UpdatedAt,
	)
	return err
}

func (r *%sRepository) FindByID(ctx context.Context, id string) (%sRow, error) {
	row := r.db.QueryRow(ctx,
		"SELECT id, created_at, updated_at FROM %s WHERE id = ?", id,
	)
	return scan%sRow(row)
}

func scan%sRow(row store.Row) (%sRow, error) {
	var out %sRow
	if err := row.Scan(&out.ID, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return %sRow{}, err
	}
	return out, nil
}
`, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, pascal, snake, pascal, pascal, snake, pascal, pascal, pascal, pascal, pascal)
	return path, source
}
