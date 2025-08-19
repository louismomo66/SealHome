package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sealhome/data"
	"sealhome/pkg/jwt"
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

	app := Config{
		InfoLog:       infoLog,
		ErrorLog:      errorLog,
		Wait:          &sync.WaitGroup{},
		ErrorChan:     make(chan error),
		ErrorChanDone: make(chan bool),
		OAuthConfig:   loadOAuthConfig(),
		JWTService:    jwtService,
	}

	// connect to the database and run migrations
	db := app.initDB()
	app.DB = db

	// Initialize data models after DB is ready
	app.Models = data.New(db)

	app.serve()
}
