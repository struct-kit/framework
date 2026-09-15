package controllers

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"struct-framework/internal/mvc/models"
)

// AuthService is the controller-side view of the auth dependency —
// re-declared here (not imported from services) so this package depends
// only on a method set, matching UserController's own pattern.
type AuthService interface {
	Login(ctx context.Context, email, password string) (accessToken, refreshToken, mfaTicket string, err error)
	RefreshSession(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID string) error
	EnrollTOTP(ctx context.Context, userID string) (secret, otpauthURI string, err error)
	ConfirmTOTP(ctx context.Context, userID, code string) (backupCodes []string, err error)
	DisableTOTP(ctx context.Context, userID string) error
	BackupCodesRemaining(ctx context.Context, userID string) (int, error)
	VerifyLoginTOTP(ctx context.Context, ticket, code string) (accessToken, refreshToken string, err error)

	BeginPasskeyRegistration(ctx context.Context, userID string) (ceremonyID string, challenge []byte, userName string, err error)
	FinishPasskeyRegistration(ctx context.Context, userID, ceremonyID string, clientDataJSON, attestationObject []byte, nickname string) error
	ListPasskeys(ctx context.Context, userID string) ([]models.PasskeyInfo, error)
	RenamePasskey(ctx context.Context, userID, credentialID, newName string) error
	DeletePasskey(ctx context.Context, userID, credentialID string) error
	BeginPasskeyMFA(ctx context.Context, mfaTicket string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error)
	FinishPasskeyMFA(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error)
	BeginPasskeyLogin(ctx context.Context, email string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error)
	FinishPasskeyLogin(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error)
}

type AuthController struct {
	svc AuthService
}

func NewAuthController(svc AuthService) *AuthController {
	return &AuthController{svc: svc}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse covers both outcomes of Login: either a token pair, or
// (when the account has confirmed TOTP) an MFA challenge to complete via
// POST /v1/auth/mfa/totp. Exactly one of the two shapes is populated.
type loginResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFATicket    string `json:"mfa_ticket,omitempty"`
}

func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	access, refresh, ticket, err := c.svc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if ticket != "" {
		writeJSON(w, http.StatusOK, loginResponse{MFARequired: true, MFATicket: ticket})
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{AccessToken: access, RefreshToken: refresh})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (c *AuthController) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	access, refresh, err := c.svc.RefreshSession(r.Context(), req.RefreshToken)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: access, RefreshToken: refresh})
}

func (c *AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if err := c.svc.Logout(r.Context(), req.RefreshToken); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// LogoutAll is ✱ (framework guide's marker for routes requiring a valid
// bearer token) — it needs the caller's identity, which only the Auth
// middleware can have attached.
func (c *AuthController) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	if err := c.svc.LogoutAll(r.Context(), userID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type mfaTOTPRequest struct {
	Ticket string `json:"ticket"`
	Code   string `json:"code"`
}

// VerifyMFATOTP redeems the ticket Login issued when TOTP is required,
// with either a TOTP code or a backup code.
func (c *AuthController) VerifyMFATOTP(w http.ResponseWriter, r *http.Request) {
	var req mfaTOTPRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	access, refresh, err := c.svc.VerifyLoginTOTP(r.Context(), req.Ticket, req.Code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: access, RefreshToken: refresh})
}

// EnrollTOTP is ✱: generates a new (unconfirmed) TOTP secret + otpauth://
// URI for the caller to scan into an authenticator app.
func (c *AuthController) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	secret, uri, err := c.svc.EnrollTOTP(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": uri})
}

type confirmTOTPRequest struct {
	Code string `json:"code"`
}

// ConfirmTOTP is ✱: confirms enrollment with a code and returns one-time
// backup codes — the only time they're ever shown in plaintext.
func (c *AuthController) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var req confirmTOTPRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	codes, err := c.svc.ConfirmTOTP(r.Context(), userID, req.Code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

// DisableTOTP is ✱: removes the TOTP secret and any remaining backup
// codes.
func (c *AuthController) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	if err := c.svc.DisableTOTP(r.Context(), userID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// BackupCodesRemaining is ✱: reports how many unused backup codes are
// left, without ever exposing the codes themselves again.
func (c *AuthController) BackupCodesRemaining(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	count, err := c.svc.BackupCodesRemaining(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"remaining": count})
}

// registerBeginResponse is shaped for a browser's
// navigator.credentials.create() call — the frontend base64url-decodes
// challenge itself before passing it through.
type registerBeginResponse struct {
	CeremonyID string `json:"ceremony_id"`
	Challenge  string `json:"challenge"`
	RPName     string `json:"rp_name"`
	UserName   string `json:"user_name"`
}

// BeginPasskeyRegistration is ✱: starts a WebAuthn registration ceremony.
func (c *AuthController) BeginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	ceremonyID, challenge, userName, err := c.svc.BeginPasskeyRegistration(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, registerBeginResponse{
		CeremonyID: ceremonyID,
		Challenge:  base64.RawURLEncoding.EncodeToString(challenge),
		RPName:     "Struct",
		UserName:   userName,
	})
}

type registerFinishRequest struct {
	CeremonyID        string `json:"ceremony_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
	Nickname          string `json:"nickname"`
}

// FinishPasskeyRegistration is ✱: completes registration and persists
// the new passkey.
func (c *AuthController) FinishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var req registerFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	clientDataJSON, cdErr := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	attestationObject, aoErr := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	if cdErr != nil || aoErr != nil {
		writeError(w, http.StatusBadRequest, "invalid base64url encoding", nil)
		return
	}

	if err := c.svc.FinishPasskeyRegistration(r.Context(), userID, req.CeremonyID, clientDataJSON, attestationObject, req.Nickname); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type passkeyResponse struct {
	CredentialID string `json:"credential_id"`
	Name         string `json:"name"`
	CreatedAt    string `json:"created_at"`
}

// ListPasskeys is ✱: lists the caller's registered passkeys.
func (c *AuthController) ListPasskeys(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	passkeys, err := c.svc.ListPasskeys(r.Context(), userID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	out := make([]passkeyResponse, len(passkeys))
	for i, p := range passkeys {
		out[i] = passkeyResponse{CredentialID: p.CredentialID, Name: p.Name, CreatedAt: p.CreatedAt.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

type renamePasskeyRequest struct {
	Name string `json:"name"`
}

// RenamePasskey is ✱: renames a passkey (ownership-checked by the
// service/repository layer — see postgres.WebAuthnCredentialRepository.
// Rename's doc comment for why that check lives there, not just here).
func (c *AuthController) RenamePasskey(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	var req renamePasskeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	credentialID := r.PathValue("id")
	if err := c.svc.RenamePasskey(r.Context(), userID, credentialID, req.Name); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DeletePasskey is ✱: removes a passkey (ownership-checked).
func (c *AuthController) DeletePasskey(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	credentialID := r.PathValue("id")
	if err := c.svc.DeletePasskey(r.Context(), userID, credentialID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type mfaPasskeyBeginRequest struct {
	Ticket string `json:"ticket"`
}

type mfaPasskeyBeginResponse struct {
	CeremonyID         string   `json:"ceremony_id"`
	Challenge          string   `json:"challenge"`
	AllowCredentialIDs []string `json:"allow_credential_ids"`
}

// BeginPasskeyMFA starts a passkey-as-second-factor ceremony for a
// pending login MFA ticket.
func (c *AuthController) BeginPasskeyMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaPasskeyBeginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ceremonyID, challenge, allowIDs, err := c.svc.BeginPasskeyMFA(r.Context(), req.Ticket)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mfaPasskeyBeginResponse{
		CeremonyID:         ceremonyID,
		Challenge:          base64.RawURLEncoding.EncodeToString(challenge),
		AllowCredentialIDs: allowIDs,
	})
}

type mfaPasskeyFinishRequest struct {
	CeremonyID        string `json:"ceremony_id"`
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// FinishPasskeyMFA completes a passkey-as-second-factor ceremony and
// issues tokens on success.
func (c *AuthController) FinishPasskeyMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaPasskeyFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	clientDataJSON, err1 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	authenticatorData, err2 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	signature, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusBadRequest, "invalid base64url encoding", nil)
		return
	}

	access, refresh, err := c.svc.FinishPasskeyMFA(r.Context(), req.CeremonyID, req.CredentialID, clientDataJSON, authenticatorData, signature)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: access, RefreshToken: refresh})
}

type passkeyLoginBeginRequest struct {
	Email string `json:"email"`
}

type passkeyLoginBeginResponse struct {
	CeremonyID         string   `json:"ceremony_id"`
	Challenge          string   `json:"challenge"`
	AllowCredentialIDs []string `json:"allow_credential_ids"`
}

// BeginPasskeyLogin starts a passwordless login ceremony (Pass 4d) —
// deliberately not ✱: this is how a caller authenticates in the first
// place, with no bearer token yet to present.
func (c *AuthController) BeginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginBeginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ceremonyID, challenge, allowIDs, err := c.svc.BeginPasskeyLogin(r.Context(), req.Email)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeyLoginBeginResponse{
		CeremonyID:         ceremonyID,
		Challenge:          base64.RawURLEncoding.EncodeToString(challenge),
		AllowCredentialIDs: allowIDs,
	})
}

type passkeyLoginFinishRequest struct {
	CeremonyID        string `json:"ceremony_id"`
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

// FinishPasskeyLogin completes a passwordless login ceremony and issues
// tokens directly on success — there's no password and no MFA ticket in
// this flow, since the passkey itself is the primary credential.
func (c *AuthController) FinishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	clientDataJSON, err1 := base64.RawURLEncoding.DecodeString(req.ClientDataJSON)
	authenticatorData, err2 := base64.RawURLEncoding.DecodeString(req.AuthenticatorData)
	signature, err3 := base64.RawURLEncoding.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusBadRequest, "invalid base64url encoding", nil)
		return
	}

	access, refresh, err := c.svc.FinishPasskeyLogin(r.Context(), req.CeremonyID, req.CredentialID, clientDataJSON, authenticatorData, signature)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{AccessToken: access, RefreshToken: refresh})
}
