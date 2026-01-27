package handlers

import (
	"HTTP_Server_2/internal/logger"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

// Admin
func (cfg *apiConfig) getMetrics(w http.ResponseWriter, r *http.Request) { // Shows the metric page
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(
		`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) { //reset the metric counter
	cfg.fileserverHits.Store(0)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0\n"))
}

func (cfg *apiConfig) metricsInc(next http.Handler) http.Handler { //increment the metric counter
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// api
func validateChirp(w http.ResponseWriter, r *http.Request) {
	type validateChirp struct {
		Body string `json:"body"`
	}

	var chirp validateChirp
	err := json.NewDecoder(r.Body).Decode(&chirp)
	if err != nil {
		logger.Info(fmt.Sprintf("Could not validate chirp: %s", err))
		respondWithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	if len(chirp.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	type validResponse struct {
		Valid bool `json:"valid"`
	}
	respondWithJSON(w, http.StatusOK, validResponse{Valid: true})

}
