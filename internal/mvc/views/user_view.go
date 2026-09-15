package views

import (
	"time"

	"struct-framework/internal/mvc/models"
)

// UserResponse is the only shape of a User ever sent over the wire. It
// deliberately omits PasswordHash and any other internal field, so a
// forgotten json struct tag on models.User can never leak a secret.
type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Locale    string `json:"locale"`
	CreatedAt string `json:"created_at"`
}

func FromUser(u models.User) UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Locale:    u.Locale,
		CreatedAt: u.CreatedAt.Format(time.RFC3339),
	}
}
