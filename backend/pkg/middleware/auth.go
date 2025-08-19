package middleware

import (
	"context"
	"net/http"
	"strings"

	"sealhome/pkg/jwt"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	// UserContextKey is the key used to store user information in context
	UserContextKey ContextKey = "user"
)

// AuthMiddleware creates middleware for JWT authentication
func AuthMiddleware(jwtService *jwt.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check if the header starts with "Bearer "
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			// Extract the token
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// Validate the token
			claims, err := jwtService.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Store user information in context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuthMiddleware creates middleware for optional JWT authentication
// This allows routes to work with or without authentication
func OptionalAuthMiddleware(jwtService *jwt.JWTService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the Authorization header
			authHeader := r.Header.Get("Authorization")

			if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
				// Extract the token
				tokenString := strings.TrimPrefix(authHeader, "Bearer ")

				// Validate the token
				claims, err := jwtService.ValidateToken(tokenString)
				if err == nil {
					// Store user information in context if token is valid
					ctx := context.WithValue(r.Context(), UserContextKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Continue without authentication
			next.ServeHTTP(w, r)
		})
	}
}

// RoleMiddleware creates middleware to check for specific roles
func RoleMiddleware(requiredRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user claims from context
			claims, ok := r.Context().Value(UserContextKey).(*jwt.Claims)
			if !ok {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, role := range requiredRoles {
				if claims.Role == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user claims from the request context
func GetUserFromContext(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*jwt.Claims)
	return claims, ok
}
