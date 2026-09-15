package services

import (
	"context"
	"sync"
	"time"

	"struct-framework/internal/analytics"
	"struct-framework/internal/mvc/apperr"
	"struct-framework/internal/mvc/models"
	"struct-framework/internal/platform/events"
	"struct-framework/internal/platform/security/authn"
	"struct-framework/internal/platform/security/totp"
	"struct-framework/internal/platform/security/webauthn"
	"struct-framework/internal/support/crypto"
)

// UserFinder defines the user lookup methods required by MemoryAuthService.
type UserFinder interface {
	GetUser(ctx context.Context, id string) (models.User, error)
	FindByEmail(ctx context.Context, email string) (models.User, error)
}

type memoryRefreshToken struct {
	ID        string
	UserID    string
	FamilyID  string
	TokenHash string
	ExpiresAt time.Time
	Revoked   bool
}

type memoryTOTPRecord struct {
	UserID          string
	EncryptedSecret string
	Confirmed       bool
}

type memoryPasskeyRecord struct {
	CredentialID string
	UserID       string
	PublicKeyX   string
	PublicKeyY   string
	SignCount    int64
	Nickname     string
	CreatedAt    time.Time
}

// MemoryAuthService is an in-memory implementation of controllers.AuthService
// allowing full authentication, session rotation, TOTP MFA, and WebAuthn passkeys
// to run with zero external database dependencies.
type MemoryAuthService struct {
	users         UserFinder
	signingKey    []byte
	encryptionKey []byte
	rpConfig      webauthn.Config

	events    events.Publisher
	analytics *analytics.Publisher

	pendingMFA        *pendingMFAStore
	passkeyCeremonies *webauthnCeremonyStore

	mu sync.RWMutex

	// Lockout and attempts
	failedAttempts map[string]int
	lockedUntil    map[string]time.Time

	// Refresh tokens
	tokens       map[string]*memoryRefreshToken // key: TokenHash
	tokensByID   map[string]*memoryRefreshToken // key: TokenID
	familyTokens map[string][]string            // key: FamilyID -> []TokenID

	// TOTP
	totpRecords map[string]*memoryTOTPRecord // key: UserID
	backupCodes map[string][]string          // key: UserID -> hashed codes

	// Passkeys
	passkeys       map[string]*memoryPasskeyRecord // key: CredentialID
	passkeysByUser map[string][]string             // key: UserID -> []CredentialID
}

func NewMemoryAuthService(
	users UserFinder,
	signingKey, encryptionKey []byte,
	rpConfig webauthn.Config,
) *MemoryAuthService {
	return &MemoryAuthService{
		users:             users,
		signingKey:        signingKey,
		encryptionKey:     encryptionKey,
		rpConfig:          rpConfig,
		pendingMFA:        newPendingMFAStore(),
		passkeyCeremonies: newWebAuthnCeremonyStore(),
		failedAttempts:    make(map[string]int),
		lockedUntil:       make(map[string]time.Time),
		tokens:            make(map[string]*memoryRefreshToken),
		tokensByID:        make(map[string]*memoryRefreshToken),
		familyTokens:      make(map[string][]string),
		totpRecords:       make(map[string]*memoryTOTPRecord),
		backupCodes:       make(map[string][]string),
		passkeys:          make(map[string]*memoryPasskeyRecord),
		passkeysByUser:    make(map[string][]string),
	}
}

func (s *MemoryAuthService) SetEventPublisher(p events.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = p
}

func (s *MemoryAuthService) SetAnalyticsPublisher(p *analytics.Publisher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analytics = p
}

func (s *MemoryAuthService) Login(ctx context.Context, email, password string) (accessToken, refreshToken, mfaTicket string, err error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return "", "", "", apperr.Unauthorized("invalid credentials")
	}

	s.mu.Lock()
	now := time.Now().UTC()
	if lockTime, exists := s.lockedUntil[user.ID]; exists && now.Before(lockTime) {
		s.mu.Unlock()
		return "", "", "", apperr.Unauthorized("account is temporarily locked")
	}

	ok, _ := crypto.VerifyPassword(password, user.PasswordHash)
	if !ok {
		s.failedAttempts[user.ID]++
		if s.failedAttempts[user.ID] >= maxLoginAttempts {
			s.lockedUntil[user.ID] = now.Add(lockoutDuration)
		}
		s.mu.Unlock()
		return "", "", "", apperr.Unauthorized("invalid credentials")
	}

	s.failedAttempts[user.ID] = 0
	delete(s.lockedUntil, user.ID)

	// Check if TOTP is enabled
	hasTOTP := false
	if totpRec, exists := s.totpRecords[user.ID]; exists && totpRec.Confirmed {
		hasTOTP = true
	}
	s.mu.Unlock()

	if hasTOTP {
		ticket, issueErr := s.pendingMFA.Issue(user.ID)
		if issueErr != nil {
			return "", "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue mfa ticket", issueErr)
		}
		return "", "", ticket, nil
	}

	access, refresh, issueErr := s.issueTokenPair(ctx, user.ID, newFamilyID())
	if issueErr != nil {
		return "", "", "", issueErr
	}

	s.emitLoginEvents(ctx, user.ID)
	return access, refresh, "", nil
}

func (s *MemoryAuthService) RefreshSession(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	tokenHash := authn.HashToken(refreshToken)

	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.tokens[tokenHash]
	if !ok || time.Now().UTC().After(tok.ExpiresAt) {
		return "", "", apperr.Unauthorized("invalid or expired refresh token")
	}

	if tok.Revoked {
		// Token reuse attack detected! Revoke all tokens in family.
		for _, tokenID := range s.familyTokens[tok.FamilyID] {
			if t, found := s.tokensByID[tokenID]; found {
				t.Revoked = true
			}
		}
		return "", "", apperr.Unauthorized("refresh token reuse detected; all sessions revoked")
	}

	tok.Revoked = true

	newRawToken, err := newRefreshTokenID()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate refresh token", err)
	}
	newHash := authn.HashToken(newRawToken)

	newTok := &memoryRefreshToken{
		ID:        newRawToken,
		UserID:    tok.UserID,
		FamilyID:  tok.FamilyID,
		TokenHash: newHash,
		ExpiresAt: time.Now().UTC().Add(refreshTokenTTL),
		Revoked:   false,
	}

	s.tokens[newHash] = newTok
	s.tokensByID[newRawToken] = newTok
	s.familyTokens[tok.FamilyID] = append(s.familyTokens[tok.FamilyID], newRawToken)

	newAccess, err := authn.IssueJWT(tok.UserID, accessTokenTTL, s.signingKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue access token", err)
	}

	return newAccess, newRawToken, nil
}

func (s *MemoryAuthService) Logout(ctx context.Context, refreshToken string) error {
	tokenHash := authn.HashToken(refreshToken)

	s.mu.Lock()
	defer s.mu.Unlock()

	tok, ok := s.tokens[tokenHash]
	if !ok {
		return nil
	}

	for _, tokenID := range s.familyTokens[tok.FamilyID] {
		if t, found := s.tokensByID[tokenID]; found {
			t.Revoked = true
		}
	}
	return nil
}

func (s *MemoryAuthService) LogoutAll(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, tok := range s.tokensByID {
		if tok.UserID == userID {
			tok.Revoked = true
		}
	}
	return nil
}

func (s *MemoryAuthService) EnrollTOTP(ctx context.Context, userID string) (secret, otpauthURI string, err error) {
	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return "", "", apperr.NotFound("user not found")
	}

	plainSecret, err := totp.GenerateSecret()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate totp secret", err)
	}

	encSecret, err := crypto.EncryptField(plainSecret, s.encryptionKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to encrypt totp secret", err)
	}

	s.mu.Lock()
	s.totpRecords[userID] = &memoryTOTPRecord{
		UserID:          userID,
		EncryptedSecret: encSecret,
		Confirmed:       false,
	}
	s.mu.Unlock()

	uri := totp.BuildURI(plainSecret, "Struct", u.Email)
	return plainSecret, uri, nil
}

func (s *MemoryAuthService) ConfirmTOTP(ctx context.Context, userID, code string) (backupCodes []string, err error) {
	s.mu.Lock()
	rec, ok := s.totpRecords[userID]
	if !ok {
		s.mu.Unlock()
		return nil, apperr.NotFound("no pending totp enrollment found")
	}

	plainSecret, err := crypto.DecryptField(rec.EncryptedSecret, s.encryptionKey)
	if err != nil {
		s.mu.Unlock()
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to decrypt totp secret", err)
	}

	valid, _ := totp.Verify(plainSecret, code)
	if !valid {
		s.mu.Unlock()
		return nil, apperr.Unauthorized("invalid verification code")
	}

	rec.Confirmed = true

	plainCodes, err := totp.GenerateBackupCodes(backupCodeCount)
	if err != nil {
		s.mu.Unlock()
		return nil, apperr.Wrap(apperr.KindUnknown, "failed to generate backup codes", err)
	}

	var hashedCodes []string
	for _, c := range plainCodes {
		h, hashErr := crypto.HashPassword(c)
		if hashErr != nil {
			s.mu.Unlock()
			return nil, apperr.Wrap(apperr.KindUnknown, "failed to hash backup code", hashErr)
		}
		hashedCodes = append(hashedCodes, h)
	}
	s.backupCodes[userID] = hashedCodes
	s.mu.Unlock()

	return plainCodes, nil
}

func (s *MemoryAuthService) DisableTOTP(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totpRecords, userID)
	delete(s.backupCodes, userID)
	return nil
}

func (s *MemoryAuthService) BackupCodesRemaining(ctx context.Context, userID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.backupCodes[userID]), nil
}

func (s *MemoryAuthService) VerifyLoginTOTP(ctx context.Context, ticket, code string) (accessToken, refreshToken string, err error) {
	userID, ok := s.pendingMFA.Redeem(ticket)
	if !ok {
		return "", "", apperr.Unauthorized("invalid or expired mfa ticket")
	}

	s.mu.Lock()
	rec, hasTOTP := s.totpRecords[userID]
	var plainSecret string
	if hasTOTP && rec.Confirmed {
		plainSecret, _ = crypto.DecryptField(rec.EncryptedSecret, s.encryptionKey)
	}

	verified := false
	if plainSecret != "" {
		if valid, _ := totp.Verify(plainSecret, code); valid {
			verified = true
		}
	}
	if !verified {
		// Try backup codes
		codes := s.backupCodes[userID]
		matchedIdx := -1
		for i, h := range codes {
			if match, _ := crypto.VerifyPassword(code, h); match {
				matchedIdx = i
				break
			}
		}
		if matchedIdx >= 0 {
			verified = true
			s.backupCodes[userID] = append(codes[:matchedIdx], codes[matchedIdx+1:]...)
		}
	}
	s.mu.Unlock()

	if !verified {
		return "", "", apperr.Unauthorized("invalid authentication code")
	}

	s.pendingMFA.Consume(ticket)
	access, refresh, err := s.issueTokenPair(ctx, userID, newFamilyID())
	if err != nil {
		return "", "", err
	}
	s.emitLoginEvents(ctx, userID)
	return access, refresh, nil
}

func (s *MemoryAuthService) BeginPasskeyRegistration(ctx context.Context, userID string) (ceremonyID string, challenge []byte, userName string, err error) {
	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return "", nil, "", apperr.NotFound("user not found")
	}
	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, "", apperr.Wrap(apperr.KindUnknown, "failed to start passkey registration", err)
	}
	return ceremonyID, challenge, u.Email, nil
}

func (s *MemoryAuthService) FinishPasskeyRegistration(ctx context.Context, userID, ceremonyID string, clientDataJSON, attestationObject []byte, nickname string) error {
	expectedUserID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok || expectedUserID != userID {
		return apperr.Unauthorized("passkey registration failed")
	}

	cred, err := webauthn.VerifyRegistration(s.rpConfig, challenge, clientDataJSON, attestationObject)
	if err != nil {
		return apperr.Unauthorized("passkey registration failed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pubKey := cred.PublicKey
	credID := b64Encode(cred.ID)
	rec := &memoryPasskeyRecord{
		CredentialID: credID,
		UserID:       userID,
		PublicKeyX:   b64Encode(fixedWidthBytes(pubKey.X, 32)),
		PublicKeyY:   b64Encode(fixedWidthBytes(pubKey.Y, 32)),
		SignCount:    int64(cred.SignCount),
		Nickname:     nickname,
		CreatedAt:    time.Now().UTC(),
	}
	s.passkeys[credID] = rec
	s.passkeysByUser[userID] = append(s.passkeysByUser[userID], credID)
	return nil
}

func (s *MemoryAuthService) ListPasskeys(ctx context.Context, userID string) ([]models.PasskeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []models.PasskeyInfo
	for _, id := range s.passkeysByUser[userID] {
		if pk, found := s.passkeys[id]; found {
			result = append(result, models.PasskeyInfo{
				CredentialID: pk.CredentialID,
				Name:         pk.Nickname,
				CreatedAt:    pk.CreatedAt,
			})
		}
	}
	return result, nil
}

func (s *MemoryAuthService) RenamePasskey(ctx context.Context, userID, credentialID, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pk, ok := s.passkeys[credentialID]
	if !ok || pk.UserID != userID {
		return apperr.NotFound("passkey not found")
	}
	pk.Nickname = newName
	return nil
}

func (s *MemoryAuthService) DeletePasskey(ctx context.Context, userID, credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pk, ok := s.passkeys[credentialID]
	if !ok || pk.UserID != userID {
		return apperr.NotFound("passkey not found")
	}
	delete(s.passkeys, credentialID)

	var updated []string
	for _, id := range s.passkeysByUser[userID] {
		if id != credentialID {
			updated = append(updated, id)
		}
	}
	s.passkeysByUser[userID] = updated
	return nil
}

func (s *MemoryAuthService) BeginPasskeyMFA(ctx context.Context, mfaTicket string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
	userID, ok := s.pendingMFA.Redeem(mfaTicket)
	if !ok {
		return "", nil, nil, apperr.Unauthorized("invalid or expired mfa ticket")
	}

	s.mu.RLock()
	allowCredentialIDs = append([]string(nil), s.passkeysByUser[userID]...)
	s.mu.RUnlock()

	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, nil, apperr.Wrap(apperr.KindUnknown, "failed to start passkey mfa", err)
	}
	return ceremonyID, challenge, allowCredentialIDs, nil
}

func (s *MemoryAuthService) FinishPasskeyMFA(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
	expectedUserID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok {
		return "", "", apperr.Unauthorized("passkey verification failed")
	}

	s.mu.Lock()
	cred, exists := s.passkeys[credentialID]
	if !exists || cred.UserID != expectedUserID {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized("passkey verification failed")
	}

	pubKey, err := reconstructECDSAPublicKey(cred.PublicKeyX, cred.PublicKeyY)
	if err != nil {
		s.mu.Unlock()
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to reconstruct passkey public key", err)
	}

	newSignCount, err := webauthn.VerifyAssertion(
		s.rpConfig, challenge, pubKey, uint32(cred.SignCount), clientDataJSON, authenticatorData, signature)
	if err != nil {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized("passkey verification failed")
	}
	cred.SignCount = int64(newSignCount)
	s.mu.Unlock()

	access, refresh, err := s.issueTokenPair(ctx, expectedUserID, newFamilyID())
	if err != nil {
		return "", "", err
	}
	s.emitLoginEvents(ctx, expectedUserID)
	return access, refresh, nil
}

func (s *MemoryAuthService) BeginPasskeyLogin(ctx context.Context, email string) (ceremonyID string, challenge []byte, allowCredentialIDs []string, err error) {
	var userID string
	if email != "" {
		if u, findErr := s.users.FindByEmail(ctx, email); findErr == nil {
			userID = u.ID
			s.mu.RLock()
			allowCredentialIDs = append([]string(nil), s.passkeysByUser[userID]...)
			s.mu.RUnlock()
		}
	}

	ceremonyID, challenge, err = s.passkeyCeremonies.Issue(userID)
	if err != nil {
		return "", nil, nil, apperr.Wrap(apperr.KindUnknown, "failed to start passkey login", err)
	}
	return ceremonyID, challenge, allowCredentialIDs, nil
}

func (s *MemoryAuthService) FinishPasskeyLogin(ctx context.Context, ceremonyID, credentialID string, clientDataJSON, authenticatorData, signature []byte) (accessToken, refreshToken string, err error) {
	const genericFailure = "passkey login failed"

	userID, challenge, ok := s.passkeyCeremonies.Redeem(ceremonyID)
	if !ok {
		return "", "", apperr.Unauthorized(genericFailure)
	}

	s.mu.Lock()
	cred, exists := s.passkeys[credentialID]
	if !exists {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized(genericFailure)
	}

	if userID != "" && cred.UserID != userID {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized(genericFailure)
	}
	userID = cred.UserID
	if userID == "" {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized(genericFailure)
	}

	pubKey, err := reconstructECDSAPublicKey(cred.PublicKeyX, cred.PublicKeyY)
	if err != nil {
		s.mu.Unlock()
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to reconstruct passkey public key", err)
	}

	newSignCount, err := webauthn.VerifyAssertion(
		s.rpConfig, challenge, pubKey, uint32(cred.SignCount), clientDataJSON, authenticatorData, signature)
	if err != nil {
		s.mu.Unlock()
		return "", "", apperr.Unauthorized(genericFailure)
	}
	cred.SignCount = int64(newSignCount)
	s.mu.Unlock()

	access, refresh, err := s.issueTokenPair(ctx, userID, newFamilyID())
	if err != nil {
		return "", "", err
	}
	s.emitLoginEvents(ctx, userID)
	return access, refresh, nil
}

func (s *MemoryAuthService) issueTokenPair(ctx context.Context, userID, familyID string) (accessToken, refreshToken string, err error) {
	access, err := authn.IssueJWT(userID, accessTokenTTL, s.signingKey)
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to issue access token", err)
	}

	rawRefresh, err := newRefreshTokenID()
	if err != nil {
		return "", "", apperr.Wrap(apperr.KindUnknown, "failed to generate refresh token", err)
	}
	tokenHash := authn.HashToken(rawRefresh)

	s.mu.Lock()
	tok := &memoryRefreshToken{
		ID:        rawRefresh,
		UserID:    userID,
		FamilyID:  familyID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().UTC().Add(refreshTokenTTL),
		Revoked:   false,
	}
	s.tokens[tokenHash] = tok
	s.tokensByID[rawRefresh] = tok
	s.familyTokens[familyID] = append(s.familyTokens[familyID], rawRefresh)
	s.mu.Unlock()

	return access, rawRefresh, nil
}

func (s *MemoryAuthService) emitLoginEvents(ctx context.Context, userID string) {
	s.mu.RLock()
	evPub := s.events
	anPub := s.analytics
	s.mu.RUnlock()

	if evPub != nil {
		_ = evPub.Publish(ctx, events.Event{
			ID:          newFamilyID(),
			Name:        "UserLoggedInV1",
			AggregateID: userID,
			OccurredAt:  time.Now().UTC(),
			Payload:     map[string]any{"user_id": userID},
		})
	}
	if anPub != nil {
		anPub.Track(analytics.Event{
			Name:      "UserLoggedIn",
			UserID:    userID,
			Timestamp: time.Now().UTC(),
		})
	}
}
