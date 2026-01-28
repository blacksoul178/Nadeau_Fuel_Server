## Vibe Coded because this is way out of my league atm


# HTTPS/TLS Setup Guide for Nadeau Fuel Server

## Development Setup (Self-Signed Certificate)

For development without a proper certificate, you can use a self-signed certificate:

### 1. Generate Self-Signed Certificate

```powershell
# Generate private key and certificate (valid for 365 days)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Or use Go's built-in tools:
go run crypto/tls
```

**OR using PowerShell:**

```powershell
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" `
  -DnsName "localhost", "127.0.0.1" `
  -FriendlyName "Nadeau Fuel Server Dev" `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -Type SSLServerAuthentication

# Export to PEM format (if needed)
Export-Certificate -Cert $cert -FilePath server.crt -Type CERT
Export-PfxCertificate -Cert $cert -FilePath server.pfx -Password (ConvertTo-SecureString -String "devpassWord123" -AsPlainText -Force)
```

### 2. Update Configuration

Edit `config.json`:

```json
{
  "session": {
    "secureCookie": true
  }
}
```

### 3. Update main.go for HTTPS

Replace `srv.ListenAndServe()` with:

```go
// For HTTPS with self-signed cert (development):
log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
```

### 4. Update handlers for HTTPS

In `internal/handlers/handlers.go`, update the CSRF cookie:

```go
func (c *CSRFManager) SetTokenCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,  // ✓ HTTPS only
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	}
	http.SetCookie(w, cookie)
}
```

## Production Setup (Let's Encrypt)

For production, use **Let's Encrypt** with **Certbot**:

### 1. Install Certbot

```bash
# Ubuntu/Debian
sudo apt-get install certbot

# Windows (via chocolatey)
choco install certbot
```

### 2. Generate Certificate

```bash
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com
```

Certificates will be at: `/etc/letsencrypt/live/yourdomain.com/`
- `privkey.pem` - private key
- `fullchain.pem` - certificate

### 3. Update main.go

```go
log.Fatal(srv.ListenAndServeTLS(
	"/etc/letsencrypt/live/yourdomain.com/fullchain.pem",
	"/etc/letsencrypt/live/yourdomain.com/privkey.pem",
))
```

### 4. Auto-Renewal

```bash
# Add to crontab
0 3 * * * certbot renew --quiet
```

## Security Headers for HTTPS

Add security headers middleware:

```go
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// In App() function:
mux := &http.ServeMux{}
mux.HandleFunc(...) // your routes
wrappedMux := securityHeaders(mux)
srv := &http.Server{Handler: wrappedMux, ...}
```

## Testing HTTPS Locally

```bash
# With self-signed cert (ignores certificate warnings)
curl -k https://localhost:8443

# Browser: https://localhost:8443/login
# Browser will show certificate warning - click "Advanced" then proceed
```

## SSL/TLS Configuration Best Practices

```go
srv := &http.Server{
	Addr:    ":8443",
	Handler: mux,
	TLSConfig: &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	},
	IdleTimeout:  5 * time.Minute,
	ReadTimeout:  10 * time.Second,
	WriteTimeout: 10 * time.Second,
}

log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
```

## Redirect HTTP to HTTPS (Production)

```go
// Start HTTP server that redirects to HTTPS
go func() {
	log.Printf("HTTP redirect server on :8080")
	httpServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.Path
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
	}
	log.Fatal(httpServer.ListenAndServe())
}()

// HTTPS server
log.Fatal(srv.ListenAndServeTLS("cert.pem", "key.pem"))
```

## Current Status

✓ **Development**: Working with `secureCookie: false` (HTTP)  
⚠️ **Next Step**: Implement HTTPS with self-signed cert  
🎯 **Production**: Use Let's Encrypt certificate
