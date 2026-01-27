package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"net/http"
	"strings"
)

// SessionInfo holds the parsed session cookie data
type SessionInfo struct {
	Username string
	Role     string
}

// GetSessionInfo parses the session cookie and returns the user info
func GetSessionInfo(r *http.Request) *SessionInfo {
	c, err := r.Cookie("session")
	if err != nil || c.Value == "" {
		return nil
	}

	parts := strings.Split(c.Value, "|")
	if len(parts) != 2 {
		return nil
	}

	return &SessionInfo{
		Username: parts[0],
		Role:     parts[1],
	}
}

// IsAdmin checks if the user is an admin
func IsAdmin(r *http.Request) bool {
	session := GetSessionInfo(r)
	return session != nil && session.Role == "admin"
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Si déjà connecté → home
	if c, _ := r.Cookie("session"); c != nil && c.Value != "" && r.Method == "GET" {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case "GET":
		_ = tplLogin.Execute(w, nil)
	case "POST":
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := AuthenticateUser(db, username, password)
		if err != nil {
			logger.Info("Login failed: " + err.Error())
			_ = tplLogin.Execute(w, map[string]string{"Error": "Identifiants invalides"})
			return
		}
		logger.Info("Login successful for user: " + user.Username)

		// Build cookie value with role information
		role := "user"
		if user.IsAdmin {
			role = "admin"
		}
		cookieValue := user.Username + "|" + role

		http.SetCookie(w, &http.Cookie{Name: "session", Value: cookieValue, Path: "/"})
		logger.Info("Cookie set, redirecting to /home")
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	default:
		http.Error(w, "Méthode non supportée", http.StatusMethodNotAllowed)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	session := GetSessionInfo(r)
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Username": session.Username,
		"Role":     session.Role,
		"IsAdmin":  session.Role == "admin",
	}

	_ = tplHome.Execute(w, data)
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || c.Value == "" {
			logger.Info(err.Error())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}
