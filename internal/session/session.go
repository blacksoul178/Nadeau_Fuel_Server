package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// SessionData represents the data stored in a session cookie
type SessionData struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenID   string    `json:"token_id"` // Random token for invalidation
}

// Manager handles secure session creation and validation
type Manager struct {
	secretKey  []byte
	maxAge     int // in seconds
	sameSite   http.SameSite
	secure     bool
	httpOnly   bool
	cookieName string
}

// NewManager creates a new session manager
func NewManager(secretKey []byte, maxAgeSeconds int, secure bool) *Manager {
	if len(secretKey) < 32 {
		panic("secret key must be at least 32 bytes for security")
	}

	return &Manager{
		secretKey:  secretKey,
		maxAge:     maxAgeSeconds,
		sameSite:   http.SameSiteLaxMode,
		secure:     secure, // should be true in production (HTTPS only)
		httpOnly:   true,   // protects against XSS
		cookieName: "session",
	}
}

// CreateSession creates and signs a new session cookie
func (m *Manager) CreateSession(username, role string) (*http.Cookie, error) {
	// Generate random token ID for session invalidation
	tokenID, err := generateRandomToken(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	data := SessionData{
		Username:  username,
		Role:      role,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Duration(m.maxAge) * time.Second),
		TokenID:   tokenID,
	}

	// Serialize and sign the session data
	value, err := m.encodeAndSignSession(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session: %w", err)
	}

	cookie := &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   m.maxAge,
		Expires:  data.ExpiresAt,
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	}

	return cookie, nil
}

// ValidateSession validates and decodes a session cookie
func (m *Manager) ValidateSession(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie not found: %w", err)
	}

	if cookie.Value == "" {
		return nil, errors.New("session cookie is empty")
	}

	data, err := m.decodeAndVerifySession(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session: %w", err)
	}

	// Check expiration
	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session has expired")
	}

	return data, nil
}

// DeleteSession creates a cookie to delete the session
func (m *Manager) DeleteSession() *http.Cookie {
	return &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: m.httpOnly,
		Secure:   m.secure,
		SameSite: m.sameSite,
	}
}

// encodeAndSignSession serializes and signs the session data
func (m *Manager) encodeAndSignSession(data SessionData) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(jsonData)

	// Sign with HMAC-SHA256
	signature := m.sign([]byte(encoded))

	// Return as encoded|signature
	return encoded + "." + signature, nil
}

// decodeAndVerifySession verifies the signature and decodes the session data
func (m *Manager) decodeAndVerifySession(value string) (*SessionData, error) {
	// Format is: base64encodedData.hexSignature
	// Find the last dot to split them
	lastDotIndex := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			lastDotIndex = i
			break
		}
	}

	if lastDotIndex == -1 || lastDotIndex == 0 || lastDotIndex == len(value)-1 {
		return nil, errors.New("invalid session format: missing or malformed separator")
	}

	encoded := value[:lastDotIndex]
	signature := value[lastDotIndex+1:]

	// Verify signature
	expectedSignature := m.sign([]byte(encoded))
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return nil, errors.New("session signature invalid")
	}

	// Decode from base64
	jsonData, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	var data SessionData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// sign creates an HMAC signature of the data
func (m *Manager) sign(data []byte) string {
	h := hmac.New(sha256.New, m.secretKey)
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// generateRandomToken generates a random token of the specified length
func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
