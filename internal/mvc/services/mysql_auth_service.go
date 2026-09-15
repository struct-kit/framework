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
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/support/crypto"
)

// MySQLAuthService implements the identical AuthService interface
// PostgresAuthService does.
type MySQLAuthService struct {
	users             *mysql.UserRepository
	refreshTokens     *mysql.RefreshTokenRepository
	totp              *mysql.TOTPRepository
	backupCodes       *mysql.BackupCodeRepository
	passkeys          *mysql.WebAuthnCredentialRepository
	signingKey        []byte
	encryptionKey     []byte
	rpConfig          webauthn.Config
	pendingMFA        *pendingMFAStore
	passkeyCeremonies *webauthnCeremonyStore
}

func NewMySQLAuthService(
	users *mysql.UserRepository,
	refreshTokens *mysql.RefreshTokenRepository,
	totpRepo *mysql.TOTPRepository,
	backupCodes *mysql.BackupCodeRepository,
	passkeys *mysql.WebAuthnCredentialRepository,
	signingKey, encryptionKey []byte,
	rpConfig webauthn.Config,
) *MySQLAuthService {
	return &MySQLAuthService{
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

func (s *MySQLAuthService) Login(ctx context.Context, email, password string) (accessToken, refreshToken, mfaTicket string, err error) {
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

func (s *MySQLAuthService) recordFailedLogin(ctx context.Context, userID string) {
	attempts, err := s.users.IncrementFailedAttempts(ctx, userID)
	if err != nil {
		return
	}
	if attempts >= maxLoginAttempts {
		_ = s.users.LockUntil(ctx, userID, time.Now().UTC().Add(lockoutDuration))
	}
}

func (s *MySQLAuthService) issueTokenPair(ctx context.Context, userID, familyID string) (accessToken, refreshToken string, err error) {
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
	if err := s.refreshTokens.Create(ctx, mysql.RefreshTokenRow{
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

func (s *MySQLAuthService) RefreshSession(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
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
	next := mysql.RefreshTokenRow{
		ID:        id,
		TokenHash: authn.HashToken(candidate),
		Revoked:   false,
		CreatedAt: now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}

	rotated, err := s.refreshTokens.Rotate(ctx, hash, next)
	if err != nil {
		if errors.Is(err, mysql.ErrTokenReused) || errors.Is(err, mysql.ErrTokenNotFound) {
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

func (s *MySQLAuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := authn.HashToken(refreshToken)
	familyID, err := s.refreshTokens.FamilyIDByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, mysql.ErrTokenNotFound) {
			return nil
		}
		return apperr.Wrap(apperr.KindUnknown, "failed to look up session", err)
	}
	if err := s.refreshTokens.RevokeFamily(ctx, familyID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to revoke session", err)
	}
	return nil
}

func (s *MySQLAuthService) LogoutAll(ctx context.Context, userID string) error {
	if err := s.refreshTokens.RevokeAllForUser(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to revoke sessions", err)
	}
	return nil
}

func (s *MySQLAuthService) EnrollTOTP(ctx context.Context, userID string) (secret, otpauthURI string, err error) {
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
	if err := s.totp.Upsert(ctx, mysql.TOTPRow{
		UserID: userID, SecretEncrypted: encrypted, Confirmed: false, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to store totp secret", err)
	}

	return secret, totp.BuildURI(secret, "Struct", user.Email), nil
}

func (s *MySQLAuthService) ConfirmTOTP(ctx context.Context, userID, code string) ([]string, error) {
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
	rows := make([]mysql.BackupCodeRow, len(codes))
	for i, c := range codes {
		id, idErr := newRefreshTokenID()
		if idErr != nil {
			return nil, apperr.Wrap(apperr.KindUnknown, "failed to generate backup code id", idErr)
		}
		rows[i] = mysql.BackupCodeRow{ID: id, UserID: userID, CodeHash: totp.HashBackupCode(c), Used: false, CreatedAt: now}
	}
	if err := s.backupCodes.ReplaceAll(ctx, userID, rows); err != nil {
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to store backup codes", err)
	}

	return codes, nil
}

func (s *MySQLAuthService) DisableTOTP(ctx context.Context, userID string) error {
	if err := s.totp.Delete(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to disable totp", err)
	}
	if err := s.backupCodes.DeleteAllForUser(ctx, userID); err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to remove backup codes", err)
	}
	return nil
}

func (s *MySQLAuthService) BackupCodesRemaining(ctx context.Context, userID string) (int, error) {
	count, err := s.backupCodes.CountUnused(ctx, userID)
	if err != nil {
		return 0, apperr.Wrap(apperr.KindUnknown, "failed to count backup codes", err)
	}
	return count, nil
}

func (s *MySQLAuthService) VerifyLoginTOTP(ctx context.Context, ticket, code string) (accessToken, refreshToken string, err error) {
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

func (s *MySQLAuthService) BeginPasskeyRegistration(ctx context.Context, userID string) (ceremonyID string, challenge []byte, userName string, err error) {
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

func (s *MySQLAuthService) FinishPasskeyRegistration(ctx context.Context, userID, ceremonyID string, clientDataJSON, attestationObject []byte, nickname string) error {
	ceremonyUserID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok || ceremonyUserID != userID {
		return apperr.Unauthorized("passkey registration ceremony is invalid or has expired")
	}

	cred, err := webauthn.VerifyRegistration(s.rpConfig, challenge, clientDataJSON, attestationObject)
	if err != nil {
		return apperr.Unauthorized("passkey registration could not be verified")
	}

	if err := s.passkeys.Create(ctx, mysql.WebAuthnCredentialRow{
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

func (s *MySQLAuthService) ListPasskeys(ctx context.Context, userID string) ([]models.PasskeyInfo, error) {
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

func (s *MySQLAuthService) RenamePasskey(ctx context.Context, userID, credentialID, newName string) error {
	ok, err := s.passkeys.Rename(ctx, userID, credentialID, newName)
	if err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to rename passkey", err)
	}
	if !ok {
		return apperr.NotFound("passkey not found")
	}
	return nil
}

func (s *MySQLAuthService) DeletePasskey(ctx context.Context, userID, credentialID string) error {
	ok, err := s.passkeys.Delete(ctx, userID, credentialID)
	if err != nil {
		return apperr.Wrap(apperr.KindUnknown, "failed to delete passkey", err)
	}
	if !ok {
		return apperr.NotFound("passkey not found")
	}
	return nil
}

func (s *MySQLAuthService) BeginPasskeyMFA(ctx context.Context, mfaTicket string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
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

func (s *MySQLAuthService) FinishPasskeyMFA(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
	userID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok {
		return "", "", apperr.Unauthorized("passkey challenge is invalid or has expired")
	}

	cred, err := s.passkeys.FindByCredentialID(ctx, credentialID)
	if err != nil {
		return "", "", apperr.Unauthorized("passkey is invalid")
	}
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

// BeginPasskeyLogin mirrors PostgresAuthService.BeginPasskeyLogin exactly
// — see that method's doc comment for the enumeration-resistance and
// lockout-bypass reasoning, both of which apply identically here.
func (s *MySQLAuthService) BeginPasskeyLogin(ctx context.Context, email string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
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

// FinishPasskeyLogin mirrors PostgresAuthService.FinishPasskeyLogin.
func (s *MySQLAuthService) FinishPasskeyLogin(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
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
