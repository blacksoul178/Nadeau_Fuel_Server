package handlers

//Mapping of all the paths to the pages and APIs

import (
	"Nadeau_Fuel_Server/internal/logger"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
)

//go:embed chart.umd.min.js
var chartFS embed.FS

const filepathRoot = "app"

func parsePageTemplate(pageFile string) *template.Template {
	partialsPattern := filepath.Join(filepathRoot, "pages", "partials", "*.html")
	partialFiles, err := filepath.Glob(partialsPattern)
	if err != nil {
		panic(err)
	}
	pagePath := filepath.Join(filepathRoot, "pages", pageFile)
	templateName := filepath.Base(pagePath)
	files := append(partialFiles, pagePath)
	return template.Must(template.New(templateName).ParseFiles(files...))
}

// ADMIN
var tplSyncruns = parsePageTemplate("syncruns.html")
var tplLogs = parsePageTemplate("logs.html")
var tplUsers = parsePageTemplate("users.html")
var tplManual = parsePageTemplate("manual.html")

// tous
var tplLogin = parsePageTemplate("login.html")
var tplHome = parsePageTemplate("home.html")
var tplChauffeurs = parsePageTemplate("chauffeurs.html")
var tplCartes = parsePageTemplate("cartes.html")
var tplBrokers = parsePageTemplate("brokers.html")
var tplVehicules = parsePageTemplate("vehicules.html")
var tplTaux = parsePageTemplate("taux.html")
var tplPeages = parsePageTemplate("peages.html")
var tplCamionsBroker = parsePageTemplate("camionsBroker.html")
var tplbulletin = parsePageTemplate("bulletin.html")

// super user
var tplTransactions = parsePageTemplate("transactions.html")
var tplPetrolieres = parsePageTemplate("petrolieres.html")
var tplPrixFuel = parsePageTemplate("prixFuel.html")
var tplVilles = parsePageTemplate("villes.html")
var tplRampe = parsePageTemplate("rampe.html")
var tplCartesPret = parsePageTemplate("cartesPret.html")

var db *sql.DB

func App(mux *http.ServeMux, database *sql.DB) {
	// Store the database for use in handlers
	db = database

	//static files
	assets := http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(filepathRoot, "assets"))))
	mux.Handle("/assets/", assets)
	mux.Handle("/chart.umd.min.js", http.FileServer(http.FS(chartFS)))

	//all user pages routes
	mux.HandleFunc("GET /health", Health)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logOutHandler)
	mux.HandleFunc("/home", requireLogin(homeHandler))
	mux.HandleFunc("/chauffeurs", requireLogin(chauffeursHandler))
	mux.HandleFunc("/cartes", requireLogin(cartesHandler))
	mux.HandleFunc("/brokers", requireLogin(brokersHandler))
	mux.HandleFunc("/vehicules", requireLogin(vehiculesHandler))
	mux.HandleFunc("/taux", requireLogin(tauxHandler))
	mux.HandleFunc("/bulletin", requireLogin(bulletinHandler))
	//Super User pages routes
	mux.HandleFunc("/transactions", requireLogin(transactionsHandler))
	mux.HandleFunc("/petrolieres", requireLogin(petrolieresHandler))
	mux.HandleFunc("/prixFuel", requireLogin(prixFuelHandler))
	mux.HandleFunc("/villes", requireLogin(villesHandler))
	mux.HandleFunc("/rampe", requireLogin(rampeHandler))
	mux.HandleFunc("/cartesPret", requireLogin(cartesPretHandler))
	//TODO   mux.HandleFunc("/peages", requireLogin(peagesHandler))
	// Dont remember what this is mux.HandleFunc("/camionsBroker", requireLogin(camionsBrokerHandler))
	//admin pages routes
	mux.HandleFunc("/admin/syncruns", requireLogin(syncrunsHandler))
	mux.HandleFunc("/admin/logs", requireLogin(logsHandler))
	mux.HandleFunc("/admin/users", requireLogin(usersHandler))
	mux.HandleFunc("/admin/manual", requireLogin(manualHandler))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { //root
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	//Get API ALL USERS
	mux.Handle("GET /api/chauffeurs/allChauffeurs", requireLogin(http.HandlerFunc(chauffeursAllHandler)))
	mux.Handle("GET /api/chauffeurs/chauffeursPret", requireLogin(http.HandlerFunc(chauffeursPretHandler)))
	mux.Handle("GET /api/cartes/allCartes", requireLogin(http.HandlerFunc(cartesAllHandler)))
	mux.Handle("GET /api/cartesPret/allCartesPret", requireLogin(http.HandlerFunc(cartesPretAllHandler)))
	mux.Handle("GET /api/brokers/allBrokers", requireLogin(http.HandlerFunc(brokersAllHandler)))
	mux.Handle("GET /api/vehicules/allVehicules", requireLogin(http.HandlerFunc(vehiculesAllHandler)))
	mux.Handle("GET /api/taux/allWeek", requireLogin(http.HandlerFunc(tauxAllWeekHandler)))
	mux.Handle("GET /api/bulletin/monthly", requireLogin(http.HandlerFunc(bulletinMonthlyHandler)))
	mux.Handle("GET /api/bulletin/all", requireLogin(http.HandlerFunc(bulletinAllHandler)))

	//Get API Super Users
	mux.Handle("GET /api/transactions/allTransactions", requireLogin(http.HandlerFunc(transactionsAllHandler)))
	mux.Handle("GET /api/transactions/sync-status", requireLogin(http.HandlerFunc(syncStatusHandler)))
	mux.Handle("GET /api/petrolieres/allPetrolieres", requireLogin(http.HandlerFunc(petrolieresAllHandler)))
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
	mux.Handle("GET /api/villes/allVilles", requireLogin(http.HandlerFunc(villesAllHandler)))
	mux.Handle("GET /api/rampe/allRampe", requireLogin(http.HandlerFunc(rampeAllHandler)))
	// TODO   mux.Handle("GET /api/peages/all", requireLogin(http.HandlerFunc(peagesAllHandler)))
	//mux.Handle("GET /api/camionsBroker/all", requireLogin(http.HandlerFunc(camionsBrokerAllHandler)))

	//Post API ALL USERS
	mux.Handle("POST /api/cartes/add", requireLogin(http.HandlerFunc(cartesAddHandler)))
	mux.Handle("POST /api/cartes/update", requireLogin(http.HandlerFunc(cartesUpdateHandler)))
	mux.Handle("POST /api/drivers/add", requireLogin(http.HandlerFunc(brokersAddDriver))) //Adding broker drivers
	// Update driver dispatch group
	mux.Handle("POST /api/drivers/update-group", requireLogin(http.HandlerFunc(driversUpdateGroupHandler)))

	//POST API Super USers
	mux.Handle("POST /api/cartes/delete", requireLogin(http.HandlerFunc(cartesDeleteHandler)))
	mux.Handle("POST /api/brokerCo/add", requireLogin(http.HandlerFunc(brokersAddCo)))
	mux.Handle("POST /api/transactions/update-note", requireLogin(http.HandlerFunc(updateNoteHandler)))
	mux.Handle("POST /api/petrolieres/addOilCo", requireLogin(http.HandlerFunc(petrolieresAddOilCoHandler)))
	mux.Handle("POST /api/villes/update", requireLogin(http.HandlerFunc(villesUpdateHandler)))

	// local scripts
	mux.Handle("POST /api/drivers/sync", requireLogin(http.HandlerFunc(syncDriversHandler)))
	mux.Handle("POST /api/transactions/import", requireLogin(http.HandlerFunc(importTransactionsHandler)))
	mux.Handle("POST /api/bulletin/import", requireLogin(http.HandlerFunc(importBulletinHandler)))

	//admin APIs
	mux.Handle("GET /api/admin/syncrunsError", requireLogin(http.HandlerFunc(syncrunsAllHandler)))
	mux.Handle("GET /api/admin/logs", requireLogin(http.HandlerFunc(logsApiHandler)))
	mux.Handle("GET /api/admin/users/allUsers", requireLogin(http.HandlerFunc(usersAllHandler)))
	mux.Handle("GET /api/admin/chauffeurs/allChauffeurs", requireLogin(http.HandlerFunc(adminChauffeursAllHandler)))
	mux.Handle("POST /api/admin/users/create", requireLogin(http.HandlerFunc(usersCreateHandler)))
	mux.Handle("POST /api/admin/users/delete", requireLogin(http.HandlerFunc(usersDeleteHandler)))
	mux.Handle("POST /api/admin/users/changePasswordForUser", requireLogin(http.HandlerFunc(usersChangePasswordForUserHandler)))
	mux.Handle("POST /api/admin/users/update", requireLogin(http.HandlerFunc(usersUpdateHandler)))
	mux.Handle("POST /api/admin/drivers/add", requireLogin(http.HandlerFunc(adminAddDriverHandler)))
	mux.Handle("POST /api/admin/drivers/update", requireLogin(http.HandlerFunc(adminDriversUpdateHandler)))

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
