## Vibe Coded because this is way out of my league atm

# Secure Cookie Authentication Setup Guide

## Overview
Your application now has secure cookie-based authentication with CSRF protection. This implementation includes:

### Security Features Implemented:
✅ **Encrypted & Signed Cookies** - Session data is JSON-serialized, Base64-encoded, and HMAC-SHA256 signed
✅ **HttpOnly Flag** - Prevents XSS attacks by making cookies inaccessible to JavaScript
✅ **Secure Flag** - Cookies only sent over HTTPS (configurable)
✅ **SameSite=Lax** - Mitigates CSRF attacks
✅ **Session Expiration** - Configurable TTL (default 24 hours)
✅ **CSRF Protection** - Token-based CSRF validation on login and logout
✅ **Secure Logout** - Properly invalidates sessions

---

## Configuration Required

### 1. Generate a Secure Secret Key
You **MUST** generate a proper secret key for production. Use this command to generate a 32-byte key:

**On Windows (PowerShell):**
```powershell
[Convert]::ToBase64String($(0..31 | ForEach-Object {[byte](Get-Random -Maximum 256)}))
```

**On Linux/Mac:**
```bash
openssl rand -base64 32
```

### 2. Update `config.json`

Replace the placeholder in `config.json`:
```json
{
  "session": {
    "secretKey": "PASTE_YOUR_GENERATED_BASE64_KEY_HERE",
    "maxAgeSecs": 86400,
    "secureCookie": false
  }
}
```

**Settings Explanation:**
- `secretKey`: Base64-encoded 32+ byte secret for signing cookies
- `maxAgeSecs`: Session lifetime in seconds (86400 = 24 hours)
- `secureCookie`: Set to `true` in production (requires HTTPS)

### 3. Production Settings
For production deployment:
```json
{
  "session": {
    "secretKey": "YOUR_SECURE_KEY",
    "maxAgeSecs": 3600,
    "secureCookie": true
  }
}
```

---

## Usage

### Login Flow
1. User visits `/login`
2. Server generates a CSRF token and sets it in a non-HttpOnly cookie
3. User submits form with credentials + CSRF token
4. Server validates CSRF token
5. On successful auth, server creates signed session cookie with:
   - Username
   - Role (user/admin)
   - Issue timestamp
   - Expiration timestamp
   - Random token ID

### Session Validation
The `GetSessionInfo()` function now:
1. Retrieves the signed session cookie
2. Verifies the HMAC-SHA256 signature
3. Deserializes the JSON data
4. Checks expiration
5. Returns user info or nil if invalid

### Logout
1. User submits POST to `/logout` with CSRF token
2. Server validates CSRF token
3. Session cookie is deleted (MaxAge = -1)
4. User is redirected to `/login`

---

## Code Changes Summary

### New Files
- `internal/session/session.go` - Session management with HMAC signing
- `internal/session/csrf.go` - CSRF token generation and validation

### Modified Files
- `main.go` - Initializes secure session manager
- `internal/handlers/handlers.go` - Updated login/logout with security
- `internal/handlers/app.go` - Added logout route
- `internal/config/Config.go` - Added session configuration
- `config.json` - Added session config block
- `app/pages/login.html` - Added CSRF token field
- `app/pages/home.html` - Added CSRF token to logout form

---

## Testing

### Test Login
```bash
curl -X POST http://localhost:8080/login \
  -d "username=testuser&password=testpass"
```

### Check Session Cookie
The response will include a secure `Set-Cookie` header:
```
Set-Cookie: session=<base64.signature>; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
```

### Access Protected Route
```bash
curl -b "session=<cookie_value>" http://localhost:8080/home
```

---

## Security Best Practices

1. **Always use HTTPS in production** - Set `secureCookie: true`
2. **Rotate secret keys** - Update secret key periodically
3. **Short session timeout** - Consider 1-2 hours for sensitive data
4. **Log authentication events** - Monitor failed login attempts
5. **Use strong passwords** - Enforce password policies in auth
6. **CSRF token refresh** - Tokens refresh on each request for extra security
7. **Monitor cookie tampering** - Log signature validation failures

---

## Troubleshooting

### Sessions Not Persisting
- Check that cookies are enabled in browser
- Verify `secureCookie: false` if not using HTTPS
- Ensure secret key is properly Base64-encoded

### CSRF Token Validation Fails
- Verify token matches between form submission and cookie
- Check that form includes hidden `csrf_token` field
- Ensure cookies are being sent with requests

### Signature Verification Fails
- Secret key changed between cookie creation and validation
- Cookie data was modified in transit
- Base64 encoding/decoding error

---

## API Reference

### session.Manager
```go
manager := session.NewManager(secretKey, maxAgeSecs, secureCookie)

// Create session
cookie, err := manager.CreateSession(username, role)
http.SetCookie(w, cookie)

// Validate session
data, err := manager.ValidateSession(r)

// Delete session
cookie := manager.DeleteSession()
http.SetCookie(w, cookie)
```

### session.CSRFManager
```go
csrf := session.NewCSRFManager()

// Generate token
token, err := csrf.GenerateToken()

// Set token in cookie (non-HttpOnly for JS access)
csrf.SetTokenCookie(w, token)

// Validate token
isValid := csrf.ValidateToken(r, sessionToken)
```

---

## Next Steps

1. Generate and configure your secret key
2. Test login/logout flows
3. Deploy to staging environment
4. Configure HTTPS and set `secureCookie: true`
5. Monitor authentication logs
