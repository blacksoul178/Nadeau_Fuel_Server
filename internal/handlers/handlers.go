package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"Nadeau_Fuel_Server/internal/session"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SessionInfo holds the parsed session cookie data
type SessionInfo struct {
	Username    string
	Role        string
	IsSuperUser bool
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

	isSuperUser := data.Role == "superuser"
	return &SessionInfo{
		Username:    data.Username,
		Role:        data.Role,
		IsSuperUser: isSuperUser,
	}
}

// IsAdmin checks if the user is an admin
func IsAdmin(r *http.Request) bool {
	session := GetSessionInfo(r)
	return session != nil && (session.Role == "admin" || session.Role == "superuser")
}

func IsSuperUser(r *http.Request) bool {
	session := GetSessionInfo(r)
	return session != nil && session.Role == "superuser"
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
		if user.IsSuperUser {
			role = "superuser"
		} else if user.IsAdmin {
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
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

//page handlers

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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
	}

	_ = tplCartes.Execute(w, data)
}
func transactionsHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if session.Role != "admin" && session.Role != "superuser" {
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
	}

	_ = tplTransactions.Execute(w, data)
}
func petrolieresHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if session.Role != "admin" && session.Role != "superuser" {
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
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
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     session.Role == "admin",
		"IsSuperUser": session.Role == "superuser",
		"CSRFToken":   token,
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
func logsHandler(w http.ResponseWriter, r *http.Request) {
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

	_ = tplLogs.Execute(w, data)
}
func tauxHandler(w http.ResponseWriter, r *http.Request) {
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

	_ = tplTaux.Execute(w, data)
}
func prixFuelHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if session.Role != "admin" && session.Role != "superuser" {
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

	_ = tplPrixFuel.Execute(w, data)
}

// Users handlers

func usersHandler(w http.ResponseWriter, r *http.Request) {
	if !IsAdmin(r) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	session := GetSessionInfo(r)

	// Generate fresh CSRF token
	token, err := csrfManager.GenerateToken()
	if err != nil {
		logger.Info("Failed to generate CSRF token: " + err.Error())
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	csrfManager.SetTokenCookie(w, token)

	data := map[string]interface{}{
		"Username":    session.Username,
		"Role":        session.Role,
		"IsAdmin":     IsAdmin(r),
		"IsSuperUser": session.IsSuperUser,
		"CSRFToken":   token,
	}

	if err := tplUsers.Execute(w, data); err != nil {
		logger.Info("Error executing users template: " + err.Error())
		http.Error(w, "Server error", http.StatusInternalServerError)
	}
}

func usersAllHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := `SELECT id, SiteUser, IsAdmin, IsSuperUser FROM dbo.SiteUser ORDER BY SiteUser`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		logger.Info("Query error on usersAllHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}
	defer rows.Close()

	type userOut struct {
		Id          int    `json:"id"`
		SiteUser    string `json:"SiteUser"`
		IsAdmin     bool   `json:"IsAdmin"`
		IsSuperUser bool   `json:"IsSuperUser"`
	}

	out := make([]userOut, 0, 256)

	for rows.Next() {
		var (
			id          sql.NullInt32
			siteUser    sql.NullString
			isAdmin     sql.NullBool
			isSuperUser sql.NullBool
		)
		if err := rows.Scan(&id, &siteUser, &isAdmin, &isSuperUser); err != nil {
			logger.Info("Scan error on usersAllHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Scan error")
			return
		}

		out = append(out, userOut{
			Id:          int(id.Int32),
			SiteUser:    siteUser.String,
			IsAdmin:     isAdmin.Bool,
			IsSuperUser: isSuperUser.Bool,
		})
	}

	if err := rows.Err(); err != nil {
		logger.Info("Rows error on usersAllHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Rows error")
		return
	}

	if out == nil {
		out = []userOut{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func usersCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		IsAdmin     bool   `json:"isAdmin"`
		IsSuperUser bool   `json:"isSuperUser"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	username := strings.ToLower(strings.TrimSpace(body.Username))
	password := strings.TrimSpace(body.Password)

	if username == "" || password == "" {
		respondWithError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	// Hash password with bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Info("Bcrypt error on usersCreateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	insertQ := `INSERT INTO dbo.SiteUser (SiteUser, password_hash, IsAdmin, IsSuperUser) VALUES (@username, @hash, @isAdmin, @isSuperUser)`

	if _, err := db.ExecContext(ctx, insertQ,
		sql.Named("username", username),
		sql.Named("hash", string(hash)),
		sql.Named("isAdmin", body.IsAdmin),
		sql.Named("isSuperUser", body.IsSuperUser),
	); err != nil {
		logger.Info("Insert error on usersCreateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("User %s created by %s", username, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func usersDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		ID int `json:"id"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.ID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Prevent deleting current user
	var targetUsername string
	err = db.QueryRowContext(ctx, "SELECT SiteUser FROM dbo.SiteUser WHERE id = @id", sql.Named("id", body.ID)).Scan(&targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersDeleteHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	if strings.EqualFold(targetUsername, session.Username) {
		respondWithError(w, http.StatusForbidden, "Cannot delete your own user account")
		return
	}

	// Prevent deleting last admin user
	var adminCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dbo.SiteUser WHERE IsAdmin = 1").Scan(&adminCount)
	if err != nil {
		logger.Info("Count error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	var targetIsAdmin bool
	err = db.QueryRowContext(ctx, "SELECT IsAdmin FROM dbo.SiteUser WHERE id = @id", sql.Named("id", body.ID)).Scan(&targetIsAdmin)
	if err != nil {
		logger.Info("Admin check error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if targetIsAdmin && adminCount <= 1 {
		respondWithError(w, http.StatusForbidden, "Cannot delete the last admin user")
		return
	}

	deleteQ := `DELETE FROM dbo.SiteUser WHERE id = @id`

	result, err := db.ExecContext(ctx, deleteQ, sql.Named("id", body.ID))
	if err != nil {
		logger.Info("Delete error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		logger.Info("RowsAffected error on usersDeleteHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	if rowsAffected == 0 {
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	logger.Info(fmt.Sprintf("User ID %d deleted by %s", body.ID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func usersChangePasswordForUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		UserID      int    `json:"userId"`
		NewPassword string `json:"newPassword"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.UserID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	newPassword := strings.TrimSpace(body.NewPassword)
	if newPassword == "" {
		respondWithError(w, http.StatusBadRequest, "New password is required")
		return
	}

	// Prevent admin from changing their own password via this endpoint
	var targetUsername string
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err = db.QueryRowContext(ctx, "SELECT SiteUser FROM dbo.SiteUser WHERE id = @id", sql.Named("id", body.UserID)).Scan(&targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersChangePasswordForUserHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	if strings.EqualFold(targetUsername, session.Username) {
		respondWithError(w, http.StatusForbidden, "Use the regular change password endpoint for your own password")
		return
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Info("Bcrypt error on usersChangePasswordForUserHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Password hashing error")
		return
	}

	// Update password
	updateQ := `UPDATE dbo.SiteUser SET password_hash = @hash WHERE id = @id`
	if _, err := db.ExecContext(ctx, updateQ,
		sql.Named("hash", string(newHash)),
		sql.Named("id", body.UserID),
	); err != nil {
		logger.Info("Update error on usersChangePasswordForUserHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("Password changed for user ID %d by %s", body.UserID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func usersUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !IsAdmin(r) {
		respondWithError(w, http.StatusForbidden, "Unauthorized")
		return
	}

	session := GetSessionInfo(r)

	b, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	type reqBody struct {
		UserID      int    `json:"userId"`
		NewPassword string `json:"newPassword"`
		IsAdmin     bool   `json:"isAdmin"`
		IsSuperUser bool   `json:"isSuperUser"`
	}

	var body reqBody
	if err := json.Unmarshal(b, &body); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if body.UserID <= 0 {
		respondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get target user info
	var targetUsername string
	var targetIsAdmin bool
	err = db.QueryRowContext(ctx, "SELECT SiteUser, IsAdmin FROM dbo.SiteUser WHERE id = @id", sql.Named("id", body.UserID)).Scan(&targetUsername, &targetIsAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "User not found")
		} else {
			logger.Info("Query error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
		}
		return
	}

	// Check if trying to remove admin status from last admin
	if targetIsAdmin && !body.IsAdmin {
		var adminCount int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dbo.SiteUser WHERE IsAdmin = 1").Scan(&adminCount)
		if err != nil {
			logger.Info("Count error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Database error")
			return
		}

		if adminCount <= 1 {
			respondWithError(w, http.StatusForbidden, "Cannot remove admin status from the last admin user")
			return
		}
	}

	// Build update query
	var updateQ string
	var args []interface{}

	if strings.TrimSpace(body.NewPassword) != "" {
		// Hash new password
		newHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			logger.Info("Bcrypt error on usersUpdateHandler: " + err.Error())
			respondWithError(w, http.StatusInternalServerError, "Password hashing error")
			return
		}

		updateQ = `UPDATE dbo.SiteUser SET password_hash = @hash, IsAdmin = @isAdmin, IsSuperUser = @isSuperUser WHERE id = @id`
		args = append(args,
			sql.Named("hash", string(newHash)),
			sql.Named("isAdmin", body.IsAdmin),
			sql.Named("isSuperUser", body.IsSuperUser),
			sql.Named("id", body.UserID),
		)
	} else {
		updateQ = `UPDATE dbo.SiteUser SET IsAdmin = @isAdmin, IsSuperUser = @isSuperUser WHERE id = @id`
		args = append(args,
			sql.Named("isAdmin", body.IsAdmin),
			sql.Named("isSuperUser", body.IsSuperUser),
			sql.Named("id", body.UserID),
		)
	}

	if _, err := db.ExecContext(ctx, updateQ, args...); err != nil {
		logger.Info("Update error on usersUpdateHandler: " + err.Error())
		respondWithError(w, http.StatusInternalServerError, "Database error")
		return
	}

	logger.Info(fmt.Sprintf("User ID %d updated by %s", body.UserID, session.Username))
	respondWithJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// Local Scripts
func syncDriversHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	logger.Info("Isaac sync run initiated by: " + session.Username)
	cmd := exec.Command("python", "C:\\TI_Projet_Fuel\\jobs\\Sync_Isaac.py")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Sync failed: "+err.Error()+"\n"+string(output), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Sync successful:\n" + string(output)))
}
func importTransactionsHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	logger.Info("Transaction importation initiated by: " + session.Username)
	cmd := exec.Command("python", "C:\\TI_Projet_Fuel\\jobs\\Transactions\\import_transactions.py")
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, "Importation failed: "+err.Error()+"\n"+string(output), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("Importation successful:\n" + string(output)))
}
