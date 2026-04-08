package handlers

//Mapping of all the paths to the pages and APIs

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
var tplTaux = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "taux.html")))
var tplPrixFuel = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "prixFuel.html")))
var tplVilles = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "villes.html")))
var tplPetitsVehicules = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "petitsVehicules.html")))
var tplRampe = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "rampe.html")))
var tplPeages = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "peages.html")))
var tplCamionsBroker = template.Must(template.ParseFiles(filepath.Join(filepathRoot, "pages", "camionsBroker.html")))

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
	mux.HandleFunc("/taux", requireLogin(tauxHandler))
	mux.HandleFunc("/prixFuel", requireLogin(prixFuelHandler))
	mux.HandleFunc("/villes", requireLogin(villesHandler))
	mux.HandleFunc("/peages", requireLogin(peagesHandler))
	mux.HandleFunc("/camionsBroker", requireLogin(camionsBrokerHandler))
	// mux.HandleFunc("/petitsVehicules", requireLogin(petitsVehiculesHandler))
	mux.HandleFunc("/rampe", requireLogin(rampeHandler))
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
	mux.Handle("GET /api/taux/allWeek", requireLogin(http.HandlerFunc(tauxAllWeekHandler)))
	mux.Handle("GET /api/prixFuel/globalJour", requireLogin(http.HandlerFunc(prixFuelGlobalJourHandler)))
	mux.Handle("GET /api/prixFuel/globalSemaine", requireLogin(http.HandlerFunc(prixFuelGlobalSemaineHandler)))
	mux.Handle("GET /api/prixFuel/diffJour", requireLogin(http.HandlerFunc(prixFuelDiffJourHandler)))
	mux.Handle("GET /api/prixFuel/diffRegionJour", requireLogin(http.HandlerFunc(prixFuelDiffRegionJourHandler)))
	mux.Handle("GET /api/prixFuel/diffSemaine", requireLogin(http.HandlerFunc(prixFuelDiffSemaineHandler)))
	mux.Handle("GET /api/prixFuel/diffRegionSemaine", requireLogin(http.HandlerFunc(prixFuelDiffRegionSemaineHandler)))
	mux.Handle("GET /api/prixFuel/regionJour", requireLogin(http.HandlerFunc(prixFuelRegionJourHandler)))
	mux.Handle("GET /api/prixFuel/jour", requireLogin(http.HandlerFunc(prixFuelJourHandler)))
	mux.Handle("GET /api/prixFuel/regionSemaine", requireLogin(http.HandlerFunc(prixFuelRegionSemaineHandler)))
	mux.Handle("GET /api/prixFuel/semaine", requireLogin(http.HandlerFunc(prixFuelSemaineHandler)))
	mux.Handle("GET /api/villes/all", requireLogin(http.HandlerFunc(villesAllHandler)))
	// mux.Handle("GET /api/petitsVehicules/all", requireLogin(http.HandlerFunc(petitsVehiculesAllHandler)))
	mux.Handle("GET /api/rampe/all", requireLogin(http.HandlerFunc(rampeAllHandler)))
	mux.Handle("GET /api/peages/all", requireLogin(http.HandlerFunc(peagesAllHandler)))
	mux.Handle("GET /api/camionsBroker/all", requireLogin(http.HandlerFunc(camionsBrokerAllHandler)))

	//Post API
	mux.Handle("POST /api/drivers/add", requireLogin(http.HandlerFunc(brokersAddDriver))) //Adding broker drivers
	mux.Handle("POST /api/brokerCo/add", requireLogin(http.HandlerFunc(brokersAddCo)))
	mux.Handle("POST /api/cartes/add", requireLogin(http.HandlerFunc(cartesAddHandler)))
	mux.Handle("POST /api/cartes/update", requireLogin(http.HandlerFunc(cartesUpdateHandler)))
	mux.Handle("POST /api/cartes/delete", requireLogin(http.HandlerFunc(cartesDeleteHandler)))
	mux.Handle("POST /api/villes/update", requireLogin(http.HandlerFunc(villesUpdateHandler)))
	// mux.Handle("POST /api/petitsVehicules/addDriver", requireLogin(http.HandlerFunc(petitsVehiculesAddDriver)))
	// mux.Handle("POST /api/petitsVehicules/update", requireLogin(http.HandlerFunc(petitsVehiculesUpdateHandler)))
	mux.Handle("POST /api/petrolieres/addOilCo", requireLogin(http.HandlerFunc(petrolieresAddOilCoHandler)))

	// local scripts
	mux.Handle("POST /api/drivers/sync", requireLogin(http.HandlerFunc(syncDriversHandler)))
	mux.Handle("POST /api/transactions/import", requireLogin(http.HandlerFunc(importTransactionsHandler)))

	//admin APIs
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
