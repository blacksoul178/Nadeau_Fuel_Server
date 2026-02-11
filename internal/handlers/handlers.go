package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"Nadeau_Fuel_Server/internal/session"
	"encoding/base64"
	"net/http"
)

// SessionInfo holds the parsed session cookie data
type SessionInfo struct {
	Username string
	Role     string
}

var sessionManager *session.Manager
var csrfManager *session.CSRFManager

// InitSecureSession initializes the secure session manager
func InitSecureSession(secretKey string, maxAgeSecs int, secureCookie bool) error {
	// Decode the base64 secret key
	decodedKey, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return err
	}

	sessionManager = session.NewManager(decodedKey, maxAgeSecs, secureCookie)
	csrfManager = session.NewCSRFManager()
	return nil
}

// GetSessionInfo validates and returns the session data
func GetSessionInfo(r *http.Request) *SessionInfo {
	if sessionManager == nil {
		return nil
	}

	data, err := sessionManager.ValidateSession(r)
	if err != nil {
		logger.Info("Session validation failed: " + err.Error())
		return nil
	}

	return &SessionInfo{
		Username: data.Username,
		Role:     data.Role,
	}
}

// IsAdmin checks if the user is an admin
func IsAdmin(r *http.Request) bool {
	session := GetSessionInfo(r)
	return session != nil && session.Role == "admin"
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// If already authenticated → home
	if GetSessionInfo(r) != nil && r.Method == "GET" {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case "GET":
		// Generate CSRF token for the form
		token, err := csrfManager.GenerateToken()
		if err != nil {
			logger.Info("Failed to generate CSRF token: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		csrfManager.SetTokenCookie(w, token)

		_ = tplLogin.Execute(w, map[string]interface{}{
			"CSRFToken": token,
		})

	case "POST":
		// Parse form
		r.ParseForm()

		// Get and validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !csrfManager.ValidateToken(csrfToken) {
			logger.Info("CSRF token validation failed")
			token, _ := csrfManager.GenerateToken()
			csrfManager.SetTokenCookie(w, token)
			_ = tplLogin.Execute(w, map[string]interface{}{
				"Error":     "Erreur de sécurité: jeton CSRF invalide",
				"CSRFToken": token,
			})
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := AuthenticateUser(db, username, password)
		if err != nil {
			logger.Info("Login failed: " + err.Error())
			token, _ := csrfManager.GenerateToken()
			csrfManager.SetTokenCookie(w, token)
			_ = tplLogin.Execute(w, map[string]interface{}{
				"Error":     "Identifiants invalides",
				"CSRFToken": token,
			})
			return
		}

		logger.Info("Login successful for user: " + user.Username)

		// Create secure session cookie
		role := "user"
		if user.IsAdmin {
			role = "admin"
		}

		sessionCookie, err := sessionManager.CreateSession(user.Username, role)
		if err != nil {
			logger.Info("Failed to create session: " + err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, sessionCookie)

		// Delete CSRF cookie after successful login
		csrfDeleteCookie := &http.Cookie{
			Name:     "csrf_token",
			Value:    "",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: false,
		}
		http.SetCookie(w, csrfDeleteCookie)

		logger.Info("Secure session created, redirecting to /home")
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return

	default:
		http.Error(w, "Méthode non supportée", http.StatusMethodNotAllowed)
	}
}

func logOutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Méthode non supportée", http.StatusMethodNotAllowed)
		return
	}

	// Validate CSRF token for logout
	r.ParseForm()
	csrfToken := r.FormValue("csrf_token")

	if !csrfManager.ValidateToken(csrfToken) {
		logger.Info("CSRF token validation failed for logout")
		http.Error(w, "Erreur de sécurité", http.StatusForbidden)
		return
	}

	// Delete the session cookie
	sessionDeleteCookie := sessionManager.DeleteSession()
	http.SetCookie(w, sessionDeleteCookie)

	// Delete CSRF cookie
	csrfDeleteCookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: false,
	}
	http.SetCookie(w, csrfDeleteCookie)

	logger.Info("User logged out successfully")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplHome.Execute(w, data)
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := GetSessionInfo(r)
		if session == nil {
			logger.Info("Authentication required but session invalid")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

type PageData struct {
	Username  string
	Role      string
	IsAdmin   bool
	CSRFToken string
	ActiveTab string
}

func chauffeursHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplChauffeurs.Execute(w, data)
}
func cartesHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplCartes.Execute(w, data)
}
func transactionsHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplTransactions.Execute(w, data)
}
func petrolieresHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplPetrolieres.Execute(w, data)
}
func vehiculesHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplVehicules.Execute(w, data)
}
func brokersHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplBrokers.Execute(w, data)
}
func syncrunsHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if session.Role != "admin" {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	// Generate fresh CSRF token for any forms on the page
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":  session.Username,
		"Role":      session.Role,
		"IsAdmin":   session.Role == "admin",
		"CSRFToken": token,
	}

	_ = tplSyncruns.Execute(w, data)
}
