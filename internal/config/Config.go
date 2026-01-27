package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type AppConfig struct {
	Server ServerCfg `json:"server"`
	Logger LoggerCfg `json:"logger"`

	// Other configs
}

type LoggerCfg struct {
	Level      string `json:"level"`      // e.g., "info", "debug", "error"
	OutputPath string `json:"outputPath"` // e.g., "server.log", or "stdout"
	Format     string `json:"format"`     // e.g., "json", "text"
	AppName    string `json:"appName"`    //e.g., app name in the log file
	// Add more fields as needed, like `MaxSize`, `MaxBackups` for log rotation
}

type ServerCfg struct {
	Port string `json:"port"` //server runs on port
}

func LoadAppConfig(configPath string) (AppConfig, error) {
	configFile, err := os.Open(configPath)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to open config file %s: %w", configPath, err)
	}
	defer configFile.Close()

	byteValue, err := io.ReadAll(configFile)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var appConfig AppConfig
	err = json.Unmarshal(byteValue, &appConfig)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to unmarshal config from %s: %w", configPath, err)
	}

	return appConfig, nil
}
