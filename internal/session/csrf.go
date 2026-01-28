package session

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// CSRFManager handles CSRF token generation and validation
type CSRFManager struct {
	tokenLength int
	store       *sync.Map // thread-safe map to store tokens with expiry
}

// tokenEntry holds a token and its expiry time
type tokenEntry struct {
	token     string
	expiresAt time.Time
}

// NewCSRFManager creates a new CSRF manager
func NewCSRFManager() *CSRFManager {
	manager := &CSRFManager{
		tokenLength: 32,
		store:       &sync.Map{},
	}

	// Start a goroutine to clean up expired tokens every 5 minutes
	go manager.cleanupExpiredTokens()

	return manager
}

// GenerateToken generates a new CSRF token
func (c *CSRFManager) GenerateToken() (string, error) {
	bytes := make([]byte, c.tokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(bytes)

	// Store token with 1 hour expiry
	expiresAt := time.Now().Add(1 * time.Hour)
	c.store.Store(token, tokenEntry{token: token, expiresAt: expiresAt})

	return token, nil
}

// ValidateToken validates a CSRF token
func (c *CSRFManager) ValidateToken(token string) bool {
	if token == "" {
		return false
	}

	val, ok := c.store.Load(token)
	if !ok {
		return false
	}

	entry := val.(tokenEntry)

	// Check if token has expired
	if time.Now().After(entry.expiresAt) {
		c.store.Delete(token)
		return false
	}

	// Token is valid, delete it to prevent replay attacks
	c.store.Delete(token)
	return true
}

// SetTokenCookie sets a CSRF token in a cookie for client-side tracking
func (c *CSRFManager) SetTokenCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false, // Must be false so JavaScript can read it
		Secure:   true,  // Set to true in production (HTTPS only)
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	}
	http.SetCookie(w, cookie)
}

// cleanupExpiredTokens removes expired tokens from the store
func (c *CSRFManager) cleanupExpiredTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		c.store.Range(func(key, value interface{}) bool {
			entry := value.(tokenEntry)
			if now.After(entry.expiresAt) {
				c.store.Delete(key)
			}
			return true
		})
	}
}
