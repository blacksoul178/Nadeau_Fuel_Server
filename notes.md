# Build binary for windows
GOOS=windows GOARCH=amd64 go build -o server.exe


Config.json will be external file to config the app

# internal
- logger : holds the logging logic and helpers
- config : holds the configuration extraction logic and helpers
- Handler : holds all the handler logic and helpers