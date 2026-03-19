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
var tplLogs = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "logs.html")))
var tplUsers = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "users.html")))

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
	mux.HandleFunc("/admin/logs", requireLogin(logsHandler))
	mux.HandleFunc("/admin/users", requireLogin(usersHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { //root
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	//Get API
	mux.Handle("GET /api/chauffeurs/all", requireLogin(http.HandlerFunc(chauffeursAllHandler)))
	mux.Handle("GET /api/petrolieres/all", requireLogin(http.HandlerFunc(petrolieresAllHandler)))
	mux.Handle("GET /api/vehicules/all", requireLogin(http.HandlerFunc(vehiculesAllHandler)))
	mux.Handle("GET /api/brokers/all", requireLogin(http.HandlerFunc(brokersAllHandler)))
	mux.Handle("GET /api/cartes/all", requireLogin(http.HandlerFunc(cartesAllHandler)))
	mux.Handle("GET /api/transactions/all", requireLogin(http.HandlerFunc(transactionsAllHandler)))
	mux.Handle("GET /api/transactions/sync-status", requireLogin(http.HandlerFunc(syncStatusHandler)))

	//Post API
	mux.Handle("POST /api/drivers/add", requireLogin(http.HandlerFunc(brokersAddDriver)))
	mux.Handle("POST /api/brokerCo/add", requireLogin(http.HandlerFunc(brokersAddCo)))
	mux.Handle("POST /api/cartes/add", requireLogin(http.HandlerFunc(cartesAddHandler)))
	mux.Handle("POST /api/cartes/update", requireLogin(http.HandlerFunc(cartesUpdateHandler)))
	mux.Handle("POST /api/cartes/delete", requireLogin(http.HandlerFunc(cartesDeleteHandler)))

	// local scripts
	mux.Handle("POST /api/drivers/sync", requireLogin(http.HandlerFunc(syncDriversHandler)))
	mux.Handle("POST /api/transactions/import", requireLogin(http.HandlerFunc(importTransactionsHandler)))

	//admin
	mux.Handle("GET /api/admin/syncrunsError", requireLogin(http.HandlerFunc(syncrunsAllHandler)))
	mux.Handle("GET /api/admin/logs", requireLogin(http.HandlerFunc(logsApiHandler)))
	mux.Handle("GET /api/admin/users/all", requireLogin(http.HandlerFunc(usersAllHandler)))
	mux.Handle("POST /api/admin/users/create", requireLogin(http.HandlerFunc(usersCreateHandler)))
	mux.Handle("POST /api/admin/users/delete", requireLogin(http.HandlerFunc(usersDeleteHandler)))
	mux.Handle("POST /api/admin/users/changePasswordForUser", requireLogin(http.HandlerFunc(usersChangePasswordForUserHandler)))
	mux.Handle("POST /api/admin/users/update", requireLogin(http.HandlerFunc(usersUpdateHandler)))

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
