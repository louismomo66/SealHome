package main

import (
	"log"
	"os"
	"sealhome/data"
	"sealhome/pkg/jwt"
	"sync"

	"gorm.io/gorm"
)

type Config struct {
	DB         *gorm.DB
	InfoLog    *log.Logger
	ErrorLog   *log.Logger
	Wait       *sync.WaitGroup
	Models     data.Models
	JWTService *jwt.JWTService
	// Mailer Mail
	ErrorChan     chan error
	ErrorChanDone chan bool
	OAuthConfig   OAuthConfig
}

type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	RedirectURL        string
}

func loadOAuthConfig() OAuthConfig {
	return OAuthConfig{
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", "your-google-client-id"),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", "your-google-client-secret"),
		RedirectURL:        getEnv("OAUTH_REDIRECT_URL", "http://localhost:8080/api/auth/google/callback"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
