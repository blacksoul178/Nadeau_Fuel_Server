package logger

import (
	"HTTP_Server_2/internal/config"
	"log"
	"os"
)

var defaultLogger *log.Logger

func InitLogger(cfg config.AppConfig) error {
	var output *os.File
	var err error

	if cfg.Logger.OutputPath == "stdout" {
		output = os.Stdout
	} else {
		output, err = os.OpenFile(cfg.Logger.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
	}

	// You would typically add more logic here to handle cfg.Level and cfg.Format
	defaultLogger = log.New(output, cfg.Logger.AppName, log.Ldate|log.Ltime|log.Lshortfile)
	return nil
}

func Info(message string) {
	if defaultLogger != nil {
		defaultLogger.Println("INFO: " + message)
	} else {
		log.Println("INFO: " + message) // Fallback to default if not initialized
	}
}

// Add other logging levels like Error, Warn, Debug
