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
var tplChauffeurs = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "chauffeurs.html")))
var tplCartes = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "cartes.html")))
var tplTransactions = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "transactions.html")))
var tplPetrolieres = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "petrolieres.html")))
var tplVehicules = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "vehicules.html")))
var tplBrokers = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "brokers.html")))
var tplSyncruns = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "syncruns.html")))

var db *sql.DB

func App(mux *http.ServeMux, database *sql.DB) {
	// Store the database for use in handlers
	db = database

	//static files
	assets := http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(filepathRoot, "assets"))))
	mux.Handle("/assets/", assets)

	//page routes
	mux.HandleFunc("GET /health", Health)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logOutHandler)
	mux.HandleFunc("/home", requireLogin(homeHandler))
	mux.HandleFunc("/chauffeurs", requireLogin(chauffeursHandler))
	mux.HandleFunc("/cartes", requireLogin(cartesHandler))
	mux.HandleFunc("/transactions", requireLogin(transactionsHandler))
	mux.HandleFunc("/petrolieres", requireLogin(petrolieresHandler))
	mux.HandleFunc("/vehicules", requireLogin(vehiculesHandler))
	mux.HandleFunc("/brokers", requireLogin(brokersHandler))
	mux.HandleFunc("/admin/syncruns", requireLogin(syncrunsHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { //root
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	//for development only
	mux.HandleFunc("/build", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Del("ETag")
		w.Header().Del("Last-Modified")

		var homePath = filepath.Join(filepathRoot, "pages", "cartes.html") // For Dev Only
		http.ServeFile(w, r, homePath)
	})

	//Get API
	mux.Handle("GET /api/chauffeurs/all", requireLogin(http.HandlerFunc(chauffeursAllHandler)))
	mux.Handle("GET /api/petrolieres/all", requireLogin(http.HandlerFunc(petrolieresAllHandler)))
	mux.Handle("GET /api/vehicules/all", requireLogin(http.HandlerFunc(vehiculesAllHandler)))
	mux.Handle("GET /api/brokers/all", requireLogin(http.HandlerFunc(brokersAllHandler)))
	mux.Handle("GET /api/cartes/all", requireLogin(http.HandlerFunc(cartesAllHandler)))

	//Post API
	mux.Handle("POST /api/drivers/add", requireLogin(http.HandlerFunc(brokersAddDriver)))
	mux.Handle("POST /api/brokerCo/add", requireLogin(http.HandlerFunc(brokersAddCo)))
	//admin
	mux.Handle("GET /api/admin/syncrunsError", requireLogin(http.HandlerFunc(syncrunsErrorHandler)))

}

//helpers

// for development only

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
