package main

import (
	"Nadeau_Fuel_Server/internal/config"
	"Nadeau_Fuel_Server/internal/handlers"
	"Nadeau_Fuel_Server/internal/logger"
	"fmt"
	"log"
	"net/http"
)

func main() {
	// 1- Load app configs
	appConfig, err := config.LoadAppConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading application configuration: %v", err)
	}

	// 2- Init logger
	err = logger.InitLogger(appConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// 3- Init DB connection
	db, err := initDB(appConfig.Database.Dsn)
	if err != nil {
		logger.Info(err.Error())
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 4- Create mux, map routes in the handlers package and init the server
	mux := http.NewServeMux()
	handlers.App(mux, db) //maps all routes

	srv := &http.Server{
		Addr:    ":" + appConfig.Server.Port,
		Handler: mux,
	}

	logger.Info(fmt.Sprintf("Server starting on port: %s...", appConfig.Server.Port))
	log.Printf("Serving on port: %s\n", appConfig.Server.Port)
	log.Fatal(srv.ListenAndServe())

}
