package services

import (
	"context"
	"errors"
	"time"

	"struct-framework/internal/mvc/apperr"
	"struct-framework/internal/mvc/models"
	"struct-framework/internal/platform/security/authn"
	"struct-framework/internal/platform/security/totp"
	"struct-framework/internal/platform/security/webauthn"
	"struct-framework/internal/platform/store/postgres"
	"struct-framework/internal/support/crypto"
)

// PostgresAuthService implements the AuthService interface
// internal/mvc/controllers.AuthController depends on.
type PostgresAuthService struct {
	users             *postgres.UserRepository
	refreshTokens     *postgres.RefreshTokenRepository
	totp              *postgres.TOTPRepository
	backupCodes       *postgres.BackupCodeRepository
	passkeys          *postgres.WebAuthnCredentialRepository
	signingKey        []byte
	encryptionKey     []byte
	rpConfig          webauthn.Config
	pendingMFA        *pendingMFAStore
	passkeyCeremonies *webauthnCeremonyStore
}

func NewPostgresAuthService(
	users *postgres.UserRepository,
	refreshTokens *postgres.RefreshTokenRepository,
	totpRepo *postgres.TOTPRepository,
	backupCodes *postgres.BackupCodeRepository,
	passkeys *postgres.WebAuthnCredentialRepository,
	signingKey, encryptionKey []byte,
	rpConfig webauthn.Config,
) *PostgresAuthService {
	return &PostgresAuthService{
		users:             users,
		refreshTokens:     refreshTokens,
		totp:              totpRepo,
		backupCodes:       backupCodes,
		passkeys:          passkeys,
		signingKey:        signingKey,
		encryptionKey:     encryptionKey,
		rpConfig:          rpConfig,
		pendingMFA:        newPendingMFAStore(),
		passkeyCeremonies: newWebAuthnCeremonyStore(),
	}
}

// Login verifies email+password. A nonexistent email still runs a full
// password verification against a precomputed dummy hash (framework
// guide §7.3's "timing-safe unknown-email handling"). A locked account
// is rejected before the password is even checked — no point paying the
// PBKDF2 cost for an account that can't log in anyway. On success, if
// the account has confirmed TOTP, this returns an MFA ticket instead of
// tokens; otherwise it returns tokens directly.
func (s *PostgresAuthService) Login(ctx context.Context, email, password string) (accessToken, refreshToken, mfaTicket string, err error) {
	row, findErr := s.users.FindByEmail(ctx, email)
	found := findErr == nil

	if found && !row.LockedUntil.IsZero() && time.Now().UTC().Before(row.LockedUntil) {
		return "", "", "", apperr.Locked("account is temporarily locked due to repeated failed login attempts")
	}

	hashToCheck := crypto.DummyHash()
	if found {
		hashToCheck = row.PasswordHash
	}
	valid, verifyErr := crypto.VerifyPassword(password, hashToCheck)
	if verifyErr != nil {
		return "", "", "", apperr.Wrap(apperr.KindUnknown, "failed to verify password", verifyErr)
	}

	if !found || !valid {
		if found {
			s.recordFailedLogin(ctx, row.ID)
		}
		return "", "", "", apperr.Unauthorized("invalid email or password")
	}

	if err := s.users.ResetLoginState(ctx, row.ID); err != nil {
		return "", "", "", apperr.Wrap(apperr.KindUnknown, "failed to reset login state", err)
	}

	totpRow, totpErr := s.totp.Get(ctx, row.ID)
	if totpErr == nil && totpRow.Confirmed {
		ticket, err := s.pendingMFA.Issue(row.ID)
		if err != nil {
			return "", "", "", apperr.Wrap(apperr.KindUnknown, "failed to start MFA challenge", err)
		}
		return "", "", ticket, nil
	}

	access, refresh, err := s.issueTokenPair(ctx, row.ID, newFamilyID())
	return access, refresh, "", err
}

// recordFailedLogin increments the failed-attempt counter and locks the
// account once it crosses maxLoginAttempts. Errors here are swallowed
// deliberately: a failure to update lockout bookkeeping must not itself
// turn into a 500 on top of the "invalid credentials" response the
// caller already gets.
func (s *PostgresAuthService) recordFailedLogin(ctx context.Context, userID string) {
	attempts, err := s.users.IncrementFailedAttempts(ctx, userID)
	if err != nil {
		return
	}
	if attempts >= maxLoginAttempts {
		_ = s.users.LockUntil(ctx, userID, time.Now().UTC().Add(lockoutDuration))
	}
}

func (s *PostgresAuthService) issueTokenPair(ctx context.Context, userID, familyID string) (accessToken, refreshToken string, err error) {
	access, err := authn.IssueJWT(userID, accessTokenTTL, s.signingKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue access token", err)
	}
	refresh, err := authn.NewOpaqueToken()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue refresh token", err)
	}
	id, err := newRefreshTokenID()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate token id", err)
	}

	now := time.Now().UTC()
	if err := s.refreshTokens.Create(ctx, postgres.RefreshTokenRow{
		ID:        id,
		UserID:    userID,
		TokenHash: authn.HashToken(refresh),
		FamilyID:  familyID,
		Revoked:   false,
		CreatedAt: now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}); err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to store refresh token", err)
	}

	return access, refresh, nil
}

// RefreshSession rotates refreshToken for a new pair. Presenting a token
// that was already rotated away revokes every token descended from that
// login, not just the one presented — a real theft signal.
func (s *PostgresAuthService) RefreshSession(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	hash := authn.HashToken(refreshToken)

	id, err := newRefreshTokenID()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate token id", err)
	}
	candidate, err := authn.NewOpaqueToken()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue refresh token", err)
	}

	now := time.Now().UTC()
	next := postgres.RefreshTokenRow{
		ID:        id,
		TokenHash: authn.HashToken(candidate),
		Revoked:   false,
		CreatedAt: now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}

	rotated, err := s.refreshTokens.Rotate(ctx, hash, next)
	if err != nil {
		if errors.Is(err, postgres.ErrTokenReused) || errors.Is(err, postgres.ErrTokenNotFound) {
			return "", "", apperr.Unauthorized("refresh token is invalid, expired, or has already been used")
		}
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to rotate refresh token", err)
	}

	access, err := authn.IssueJWT(rotated.UserID, accessTokenTTL, s.signingKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue access token", err)
	}
	return access, candidate, nil
}

// Logout revokes the single session refreshToken belongs to.
func (s *PostgresAuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := authn.HashToken(refreshToken)
	familyID, err := s.refreshTokens.FamilyIDByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, postgres.ErrTokenNotFound) {
			return nil // already gone — logging out twice isn't an error
		}
		return apperr.Wrap(apperr.KindUnknown, "failed to look up session", err)
	}
	if err := s.refreshTokens.RevokeFamily(ctx, familyID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to revoke session", err)
	}
	return nil
}

// LogoutAll revokes every active session for userID.
func (s *PostgresAuthService) LogoutAll(ctx context.Context, userID string) error {
	if err := s.refreshTokens.RevokeAllForUser(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to revoke sessions", err)
	}
	return nil
}

// EnrollTOTP generates a new (unconfirmed) secret and its otpauth:// URI
// for QR-code display. The secret is stored encrypted at rest
// immediately, even before confirmation — an abandoned enrollment still
// shouldn't leave a plaintext TOTP secret sitting in the database.
func (s *PostgresAuthService) EnrollTOTP(ctx context.Context, userID string) (secret, otpauthURI string, err error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to look up user", err)
	}

	secret, err = totp.GenerateSecret()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate totp secret", err)
	}
	encrypted, err := crypto.EncryptField(secret, s.encryptionKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to encrypt totp secret", err)
	}
	if err := s.totp.Upsert(ctx, postgres.TOTPRow{
		UserID: userID, SecretEncrypted: encrypted, Confirmed: false, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to store totp secret", err)
	}

	return secret, totp.BuildURI(secret, "Struct", user.Email), nil
}

// ConfirmTOTP confirms enrollment with a valid code and issues one-time
// backup recovery codes, replacing any that existed from a prior
// enrollment.
func (s *PostgresAuthService) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
	row, err := s.totp.Get(ctx, userID)
	if err != nil {
		return nil, apperr.NotFound("no pending TOTP enrollment for this account")
	}

	secret, err := crypto.DecryptField(row.SecretEncrypted, s.encryptionKey)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to decrypt totp secret", err)
	}
	ok, err := totp.Verify(secret, code)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to verify totp code", err)
	}
	if !ok {
		return nil, apperr.Unauthorized("invalid TOTP code")
	}

	if err := s.totp.Confirm(ctx, userID); err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to confirm totp enrollment", err)
	}

	codes, err := totp.GenerateBackupCodes(backupCodeCount)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to generate backup codes", err)
	}
	now := time.Now().UTC()
	rows := make([]postgres.BackupCodeRow, len(codes))
	for i, c := range codes {
		id, idErr := newRefreshTokenID() // any unique random string works as a PK here too
		if idErr != nil {
			return nil, apperr.Wrap(apperr.KindUnknown, "failed to generate backup code id", idErr)
		}
		rows[i] = postgres.BackupCodeRow{ID: id, UserID: userID, CodeHash: totp.HashBackupCode(c), Used: false, CreatedAt: now}
	}
	if err := s.backupCodes.ReplaceAll(ctx, userID, rows); err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to store backup codes", err)
	}

	return codes, nil
}

// DisableTOTP removes the TOTP secret and all remaining backup codes.
func (s *PostgresAuthService) DisableTOTP(ctx context.Context, userID string) error {
	if err := s.totp.Delete(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to disable totp", err)
	}
	if err := s.backupCodes.DeleteAllForUser(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to remove backup codes", err)
	}
	return nil
}

// BackupCodesRemaining reports how many unused backup codes are left.
func (s *PostgresAuthService) BackupCodesRemaining(ctx context.Context, userID string) (int, error) {
	count, err := s.backupCodes.CountUnused(ctx, userID)
	if err != nil {
		return 0, apperr.Wrap(apperr.KindUnknown, "failed to count backup codes", err)
	}
	return count, nil
}

// VerifyLoginTOTP redeems a login MFA ticket with a TOTP code, falling
// back to a backup code if the TOTP check fails — either way, on
// success, this issues the same token pair Login would have issued
// directly if MFA weren't required.
func (s *PostgresAuthService) VerifyLoginTOTP(ctx context.Context, ticket, code string) (accessToken, refreshToken string, err error) {
	userID, ok := s.pendingMFA.Redeem(ticket)
	if !ok {
		return "", "", apperr.Unauthorized("MFA challenge is invalid or has expired")
	}

	row, err := s.totp.Get(ctx, userID)
	if err != nil || !row.Confirmed {
		return "", "", apperr.Unauthorized("MFA challenge is invalid or has expired")
	}

	secret, err := crypto.DecryptField(row.SecretEncrypted, s.encryptionKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to decrypt totp secret", err)
	}

	valid, err := totp.Verify(secret, code)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to verify totp code", err)
	}
	if !valid {
		used, buErr := s.backupCodes.MarkUsed(ctx, userID, totp.HashBackupCode(code))
		if buErr != nil {
			return "", "", apperr.Wrap(apperr.KindUnknown, "failed to check backup code", buErr)
		}
		if !used {
			return "", "", apperr.Unauthorized("invalid TOTP or backup code")
		}
	}

	s.pendingMFA.Consume(ticket)
	return s.issueTokenPair(ctx, userID, newFamilyID())
}

// BeginPasskeyRegistration starts a WebAuthn registration ceremony for an
// already-authenticated user (this route is ✱ — registering a passkey
// requires being logged in already, which is what makes attestation
// format "none" acceptable here: the credential is trusted because the
// session registering it already was).
func (s *PostgresAuthService) BeginPasskeyRegistration(ctx context.Context, userID string) (ceremonyID string, challenge []byte, userName string, err error) {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return "", nil, "", apperr.Wrap(apperr.KindUnknown, "failed to look up user", err)
	}
	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, "", apperr.Wrap(apperr.KindUnknown, "failed to start passkey registration", err)
	}
	return ceremonyID, challenge, user.Email, nil
}

// FinishPasskeyRegistration verifies the registration ceremony and
// persists the new credential.
func (s *PostgresAuthService) FinishPasskeyRegistration(ctx context.Context, userID, ceremonyID string, clientDataJSON, attestationObject []byte, nickname string) error {
	ceremonyUserID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok || ceremonyUserID != userID {
		return apperr.Unauthorized("passkey registration ceremony is invalid or has expired")
	}

	cred, err := webauthn.VerifyRegistration(s.rpConfig, challenge, clientDataJSON, attestationObject)
	if err != nil {
		return apperr.Unauthorized("passkey registration could not be verified")
	}

	if err := s.passkeys.Create(ctx, postgres.WebAuthnCredentialRow{
		CredentialID: b64Encode(cred.ID),
		UserID:       userID,
		PublicKeyX:   b64Encode(fixedWidthBytes(cred.PublicKey.X, 32)),
		PublicKeyY:   b64Encode(fixedWidthBytes(cred.PublicKey.Y, 32)),
		SignCount:    int64(cred.SignCount),
		Name:         nickname,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to store passkey", err)
	}
	return nil
}

// ListPasskeys lists the caller's registered passkeys.
func (s *PostgresAuthService) ListPasskeys(ctx context.Context, userID string) ([]models.PasskeyInfo, error) {
	rows, err := s.passkeys.ListForUser(ctx, userID)
	if err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to list passkeys", err)
	}
	result := make([]models.PasskeyInfo, len(rows))
	for i, r := range rows {
		result[i] = models.PasskeyInfo{CredentialID: r.CredentialID, Name: r.Name, CreatedAt: r.CreatedAt}
	}
	return result, nil
}

// RenamePasskey is ownership-checked by the repository layer (see
// postgres.WebAuthnCredentialRepository.Rename's doc comment) — a caller
// can never rename another user's passkey by supplying its credential ID.
func (s *PostgresAuthService) RenamePasskey(ctx context.Context, userID, credentialID, newName string) error {
	ok, err := s.passkeys.Rename(ctx, userID, credentialID, newName)
	if err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to rename passkey", err)
	}
	if !ok {
		return apperr.NotFound("passkey not found")
	}
	return nil
}

// DeletePasskey is ownership-checked the same way RenamePasskey is.
func (s *PostgresAuthService) DeletePasskey(ctx context.Context, userID, credentialID string) error {
	ok, err := s.passkeys.Delete(ctx, userID, credentialID)
	if err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to delete passkey", err)
	}
	if !ok {
		return apperr.NotFound("passkey not found")
	}
	return nil
}

// BeginPasskeyMFA starts a passkey-as-second-factor ceremony for a login
// MFA ticket already issued by Login. Redeeming the MFA ticket here
// counts one attempt against its shared attempt budget (the same budget
// TOTP attempts on this ticket draw from) — the actual credential check
// happens in FinishPasskeyMFA.
func (s *PostgresAuthService) BeginPasskeyMFA(ctx context.Context, mfaTicket string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
	userID, ok := s.pendingMFA.Redeem(mfaTicket)
	if !ok {
		return "", nil, nil, apperr.Unauthorized("MFA challenge is invalid or has expired")
	}

	creds, err := s.passkeys.ListForUser(ctx, userID)
	if err != nil {
		return "", nil, nil, apperr.Wrap(apperr.KindUnknown, "failed to list passkeys", err)
	}
	if len(creds) == 0 {
		return "", nil, nil, apperr.NotFound("no passkeys are registered for this account")
	}
	allowCredentialIDs = make([]string, len(creds))
	for i, c := range creds {
		allowCredentialIDs[i] = c.CredentialID
	}

	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, nil, apperr.Wrap(apperr.KindUnknown, "failed to start passkey challenge", err)
	}
	return ceremonyID, challenge, allowCredentialIDs, nil
}

// FinishPasskeyMFA completes a passkey-as-second-factor ceremony and, on
// success, issues the same token pair Login would have issued directly
// if MFA weren't required.
func (s *PostgresAuthService) FinishPasskeyMFA(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
	userID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok {
		return "", "", apperr.Unauthorized("passkey challenge is invalid or has expired")
	}

	cred, err := s.passkeys.FindByCredentialID(ctx, credentialID)
	if err != nil {
		return "", "", apperr.Unauthorized("passkey is invalid")
	}
	// Defense in depth: the credential must belong to the same account
	// the MFA ticket already identified — a mismatched signature would
	// fail the check below anyway, but this keeps the error path from
	// ever reasoning about the wrong user's key.
	if cred.UserID != userID {
		return "", "", apperr.Unauthorized("passkey is invalid")
	}

	pubKey, err := reconstructECDSAPublicKey(cred.PublicKeyX, cred.PublicKeyY)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to reconstruct passkey public key", err)
	}

	newSignCount, err := webauthn.VerifyAssertion(
		s.rpConfig, challenge, pubKey, uint32(cred.SignCount), clientDataJSON, authenticatorData, signature)
	if err != nil {
		return "", "", apperr.Unauthorized("passkey verification failed")
	}

	if err := s.passkeys.UpdateSignCount(ctx, credentialID, int64(newSignCount)); err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to update passkey sign count", err)
	}

	return s.issueTokenPair(ctx, userID, newFamilyID())
}

// BeginPasskeyLogin starts a passwordless login ceremony (Pass 4d):
// unlike BeginPasskeyMFA, there's no prior password check identifying
// the account — email is the only signal. To avoid using this endpoint
// to enumerate registered emails or which accounts have passkeys
// enrolled, a ceremony is issued unconditionally, even for an unknown
// email or one with no passkeys: the ceremony is simply scoped to an
// empty user ID in that case, which FinishPasskeyLogin's ownership check
// will naturally never match against any real credential — the same
// generic failure either way, with no distinguishable timing or
// response shape.
//
// Unlike password login, this never checks LockedUntil: passkey
// possession is a fundamentally different threat model than password
// guessing — lockout exists to slow down online brute-forcing of a
// password, which a passkey login has no equivalent surface for.
func (s *PostgresAuthService) BeginPasskeyLogin(ctx context.Context, email string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
	var userID string
	if row, findErr := s.users.FindByEmail(ctx, email); findErr == nil {
		userID = row.ID
		if creds, credErr := s.passkeys.ListForUser(ctx, userID); credErr == nil {
			for _, c := range creds {
				allowCredentialIDs = append(allowCredentialIDs, c.CredentialID)
			}
		}
	}

	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, nil, apperr.Wrap(apperr.KindUnknown, "failed to start passkey login", err)
	}
	return ceremonyID, challenge, allowCredentialIDs, nil
}

// FinishPasskeyLogin completes a passwordless login ceremony. Every
// failure path returns the same generic error — an invalid ceremony, an
// unknown email from BeginPasskeyLogin (empty userID), a credential
// belonging to someone else, and a failed signature check are all
// indistinguishable to the caller, which is what keeps this endpoint
// from being useful for account enumeration.
func (s *PostgresAuthService) FinishPasskeyLogin(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
	const genericFailure = "passkey login failed"

	userID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok {
		return "", "", apperr.Unauthorized(genericFailure)
	}

	cred, err := s.passkeys.FindByCredentialID(ctx, credentialID)
	if err != nil {
		return "", "", apperr.Unauthorized(genericFailure)
	}

	// If ceremony had an expected userID (email-bound login), ensure credential belongs to that account.
	// If ceremony was discoverable/usernameless (empty userID), resolve user from the resident credential.
	if userID != "" && cred.UserID != userID {
		return "", "", apperr.Unauthorized(genericFailure)
	}
	userID = cred.UserID
	if userID == "" {
		return "", "", apperr.Unauthorized(genericFailure)
	}

	pubKey, err := reconstructECDSAPublicKey(cred.PublicKeyX, cred.PublicKeyY)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to reconstruct passkey public key", err)
	}

	newSignCount, err := webauthn.VerifyAssertion(
		s.rpConfig, challenge, pubKey, uint32(cred.SignCount), clientDataJSON, authenticatorData, signature)
	if err != nil {
		return "", "", apperr.Unauthorized(genericFailure)
	}

	if err := s.passkeys.UpdateSignCount(ctx, credentialID, int64(newSignCount)); err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to update passkey sign count", err)
	}

	return s.issueTokenPair(ctx, userID, newFamilyID())
}
