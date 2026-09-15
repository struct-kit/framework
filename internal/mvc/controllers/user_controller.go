package controllers

import (
	"context"
	"net/http"

	"struct-framework/internal/mvc/models"
	"struct-framework/internal/mvc/views"
)

// UserService is the controller-side view of the service dependency —
// deliberately re-declared here (rather than imported from services)
// so this package depends only on a method set, never a concrete type.
type UserService interface {
	CreateUser(ctx context.Context, email, password, locale string) (models.User, error)
	GetUser(ctx context.Context, id string) (models.User, error)
}

type UserController struct {
	svc UserService
}

func NewUserController(svc UserService) *UserController {
	return &UserController{svc: svc}
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Locale   string `json:"locale"`
}

func (c *UserController) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	user, err := c.svc.CreateUser(r.Context(), req.Email, req.Password, req.Locale)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, views.FromUser(user))
}

func (c *UserController) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing user id", nil)
		return
	}

	user, err := c.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, views.FromUser(user))
}
