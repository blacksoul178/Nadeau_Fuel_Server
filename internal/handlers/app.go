package handlers

import (
	"Nadeau_Fuel_Server/internal/logger"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

const filepathRoot = "app"

var tplLogin = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "login.html")))
var tplHome = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "home.html")))

var db *sql.DB

func App(mux *http.ServeMux, database *sql.DB) {
	// Store the database for use in handlers
	db = database

	//static files
	assets := http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(filepathRoot, "assets"))))
	mux.Handle("/assets/", assets)

	//page routes
	mux.HandleFunc("GET /api/health", Health)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/home", requireLogin(homeHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { //root
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	//API

	//admin

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
