package main

import (
	"Nadeau_Fuel_Server/internal/logger"
	"context"
	"database/sql"
	"time"

	_ "github.com/microsoft/go-mssqldb"
)

func initDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		errMsg := "Failed to open database: " + err.Error()
		logger.Info(errMsg)
		return nil, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(60 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		errMsg := "Failed to ping database: " + err.Error()
		logger.Info(errMsg)
		return nil, err
	}
	return db, nil
}
