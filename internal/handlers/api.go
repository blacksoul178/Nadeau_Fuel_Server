package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int
	Username string
	IsAdmin  bool
}

func normalizeUsername(u string) string {
	return strings.ToLower(strings.TrimSpace(u))
}

func AuthenticateUser(db *sql.DB, username, password string) (*User, error) {
	u := normalizeUsername(username)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var (
		id      int
		hash    string
		isAdmin bool
	)

	err := db.QueryRowContext(ctx, `
        SELECT id, password_hash, isAdmin
        FROM dbo.SiteUser
        WHERE SiteUser=@u
    `, sql.Named("u", u)).Scan(&id, &hash, &isAdmin)

	if err == sql.ErrNoRows {
		// Ne divulgue pas si l'utilisateur existe ou non
		return nil, errors.New("invalid credentials")
	}
	if err != nil {
		return nil, err
	}

	// Compare le hash bcrypt
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("invalid credentials")
	}

	return &User{
		ID:       id,
		Username: u,
		IsAdmin:  isAdmin,
	}, nil
}

// type apiConfig struct {
// }

// // Admin
// // func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) { // Shows the metric page
// // 	w.Header().Add("Content-Type", "text/html; charset=utf-8")
// // 	w.WriteHeader(http.StatusOK)
// // 	w.Write([]byte(fmt.Sprintf(
// // 		`<html>
// //   <body>
// //     <h1>Welcome, Chirpy Admin</h1>
// //     <p>Chirpy has been visited %d times!</p>
// //   </body>
// // </html>`, cfg.fileserverHits.Load())))
// // }

// // func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) { //reset the metric counter
// // 	cfg.fileserverHits.Store(0)
// // 	w.WriteHeader(http.StatusOK)
// // 	w.Write([]byte("Hits reset to 0\n"))
// // }

// // func (cfg *apiConfig) metricsInc(next http.Handler) http.Handler { //increment the metric counter
// // 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// // 		cfg.fileserverHits.Add(1)
// // 		next.ServeHTTP(w, r)
// // 	})
// // }

// // api
// // func validateChirp(w http.ResponseWriter, r *http.Request) {
// // 	type validateChirp struct {
// // 		Body string `json:"body"`
// // 	}

// // 	var chirp validateChirp
// // 	err := json.NewDecoder(r.Body).Decode(&chirp)
// // 	if err != nil {
// // 		logger.Info(fmt.Sprintf("Could not validate chirp: %s", err))
// // 		respondWithError(w, http.StatusBadRequest, "Something went wrong")
// // 		return
// // 	}
// // 	if len(chirp.Body) > 140 {
// // 		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
// // 		return
// // 	}
// // 	type validResponse struct {
// // 		Valid bool `json:"valid"`
// // 	}
// // 	respondWithJSON(w, http.StatusOK, validResponse{Valid: true})

// // }
