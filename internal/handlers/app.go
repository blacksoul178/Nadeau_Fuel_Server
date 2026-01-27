package handlers

import (
	"HTTP_Server_2/internal/logger"
	"encoding/json"
	"fmt"
	"net/http"
)

const filepathRoot = "app"

func App(mux *http.ServeMux) {
	// Register all routes here
	fileServer := http.FileServer(http.Dir(filepathRoot))
	apiCfg := apiConfig{} // init the apiconfig struct for the metrics

	//page routes
	mux.Handle("GET /app/", apiCfg.metricsInc((http.StripPrefix("/app/", fileServer)))) // Serve index.html for /app/
	mux.HandleFunc("GET /app/test", func(w http.ResponseWriter, r *http.Request) {      //custom handler to beautify urls
		http.ServeFile(w, r, "app/pages/test.html")
	})

	//API's
	mux.HandleFunc("GET /api/healthz", Healthz)
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)

	//admin
	mux.HandleFunc("GET /admin/metrics", apiCfg.getMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
}

//helpers

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	respBody := errorResponse{
		Error: msg,
	}

	data, err := json.Marshal(respBody)
	if err != nil {
		logger.Info(fmt.Sprintf("Error Marshalling JSON: %s", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Info(fmt.Sprintf("Error Marshalling JSON: %s", err.Error()))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)
}
