package main

import (
	"net/http"

	authmiddleware "sealhome/pkg/middleware"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

func (app *Config) routes() http.Handler {
	mux := chi.NewRouter()

	// Set up middleware
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Logger)

	// CORS middleware for frontend integration
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // In production, specify your frontend domain
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	// Public routes (no authentication required)
	mux.Route("/api/auth", func(r chi.Router) {
		r.Post("/login", app.LoginHandler)
		r.Post("/signup", app.SignupHandler)
		r.Post("/forgot-password", app.ForgotPasswordHandler)
		r.Post("/reset-password", app.ResetPasswordHandler)
		r.Post("/device", app.DeviceAuthHandler) // Device authentication

		// OAuth routes
		r.Get("/google", app.GoogleOAuthLoginHandler)
		r.Get("/google/callback", app.GoogleOAuthCallbackHandler)
	})

	// Protected routes (authentication required)
	mux.Route("/api", func(r chi.Router) {
		r.Use(authmiddleware.AuthMiddleware(app.JWTService))

		// User routes
		r.Route("/users", func(r chi.Router) {
			r.Get("/profile", app.GetUserProfileHandler)
			r.Put("/profile", app.UpdateUserProfileHandler)
		})

		// Device routes
		r.Route("/devices", func(r chi.Router) {
			r.Get("/", app.GetUserDevicesHandler)
			r.Get("/stats", app.GetUserDeviceStatsHandler)
			r.Post("/", app.AddDeviceHandler)
			r.Get("/{deviceID}", app.GetDeviceHandler)
			r.Put("/{deviceID}", app.UpdateDeviceHandler)
			r.Delete("/{deviceID}", app.DeleteDeviceHandler)
		})
	})

	// Health check endpoint
	mux.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	return mux
}
