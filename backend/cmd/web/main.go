package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sealhome/data"
	"sealhome/pkg/jwt"
	"sealhome/pkg/mqtt"
	"sync"

	"github.com/joho/godotenv"
)

const webPort = "9004"

func (app *Config) serve() {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", webPort),
		Handler: app.routes(),
	}
	app.InfoLog.Println("Starting web server...")
	err := srv.ListenAndServe()
	if err != nil {
		log.Panic(err)
	}
}
func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	//setup loggs
	infoLog := log.New(os.Stdout, "INFO\t", log.Ldate|log.Ltime)
	errorLog := log.New(os.Stdout, "ERROR\t", log.Ldate|log.Ltime|log.Lshortfile)

	// Initialize JWT service
	jwtService, err := jwt.NewJWTService()
	if err != nil {
		log.Fatalf("Failed to initialize JWT service: %v", err)
	}

	// Initialize MQTT manager (optional)
	mqttMgr, err := mqtt.NewManager()
	if err != nil {
		log.Printf("Warning: MQTT not connected: %v", err)
	}

	app := Config{
		InfoLog:       infoLog,
		ErrorLog:      errorLog,
		Wait:          &sync.WaitGroup{},
		ErrorChan:     make(chan error),
		ErrorChanDone: make(chan bool),
		OAuthConfig:   loadOAuthConfig(),
		JWTService:    jwtService,
		MQTT:          mqttMgr,
	}

	// connect to the database and run migrations
	db := app.initDB()
	app.DB = db

	// Initialize data models after DB is ready
	app.Models = data.New(db)

	// Subscribe to MQTT state updates and persist to DB
	if app.MQTT != nil {
		if err := app.MQTT.SubscribeStates(func(deviceID uint, peripheralType string, peripheralIndex int, state string) {
			// Persist received state to DB; ignore errors in callback to avoid blocking
			_ = app.Models.PeripheralState.SetState(deviceID, peripheralType, peripheralIndex, state)
		}); err != nil {
			log.Printf("Warning: failed to subscribe to MQTT states: %v", err)
		}
	}

	app.serve()
}
