package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"sealhome/data"
	"sealhome/pkg/middleware"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	googleoauth2 "golang.org/x/oauth2/google"
	googleoauth2api "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

// Request/Response structures
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success bool       `json:"success"`
	Token   string     `json:"token,omitempty"`
	User    *data.User `json:"user,omitempty"`
	Message string     `json:"message,omitempty"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type SignupResponse struct {
	Success bool   `json:"success"`
	UserID  uint   `json:"user_id,omitempty"`
	Message string `json:"message,omitempty"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ForgotPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

type ResetPasswordResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type GoogleOAuthRequest struct {
	Code string `json:"code"`
}

type GoogleOAuthResponse struct {
	Success bool       `json:"success"`
	Token   string     `json:"token,omitempty"`
	User    *data.User `json:"user,omitempty"`
	Message string     `json:"message,omitempty"`
}

// JWT Claims structure (keeping for backward compatibility)
type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

// In-memory storage for password reset codes (in production, use Redis or database)
var resetCodes = make(map[string]resetCodeInfo)

type resetCodeInfo struct {
	Code      string
	UserID    uint
	ExpiresAt time.Time
}

// JWT secret key is now handled by the JWT service

// getGoogleOAuthConfig returns OAuth configuration for Google
func (app *Config) getGoogleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.OAuthConfig.GoogleClientID,
		ClientSecret: app.OAuthConfig.GoogleClientSecret,
		RedirectURL:  app.OAuthConfig.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: googleoauth2.Endpoint,
	}
}

// LoginHandler handles user authentication
func (app *Config) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Get user by email
	user, err := app.Models.User.GetByEmail(req.Email)
	if err != nil {
		app.ErrorLog.Printf("Error getting user by email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Check password
	matches, err := app.Models.User.PasswordMatches(user, req.Password)
	if err != nil {
		app.ErrorLog.Printf("Error checking password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !matches {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token using the JWT service
	token, err := app.JWTService.GenerateToken(user.ID, user.Email, user.Role, nil, nil)
	if err != nil {
		app.ErrorLog.Printf("Error generating JWT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create response
	response := LoginResponse{
		Success: true,
		Token:   token,
		User:    user,
		Message: "Login successful",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// SignupHandler handles user registration
func (app *Config) SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Email == "" || req.Password == "" {
		http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := app.Models.User.GetByEmail(req.Email)
	if err != nil {
		app.ErrorLog.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if existingUser != nil {
		http.Error(w, "User with this email already exists", http.StatusConflict)
		return
	}

	// Create new user
	newUser := &data.User{
		Username: req.Username,
		Email:    req.Email,
		Phone:    req.Phone,
		Password: req.Password,
		Role:     "user", // Default role for new users
	}

	userID, err := app.Models.User.Insert(newUser)
	if err != nil {
		app.ErrorLog.Printf("Error creating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create response
	response := SignupResponse{
		Success: true,
		UserID:  userID,
		Message: "User created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// ForgotPasswordHandler initiates password reset process
func (app *Config) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Check if user exists
	user, err := app.Models.User.GetByEmail(req.Email)
	if err != nil {
		app.ErrorLog.Printf("Error getting user by email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Always return success to prevent email enumeration
	response := ForgotPasswordResponse{
		Success: true,
		Message: "If the email exists, a reset code has been sent",
	}

	// If user exists, generate and store reset code
	if user != nil {
		code := generateResetCode()
		resetCodes[req.Email] = resetCodeInfo{
			Code:      code,
			UserID:    user.ID,
			ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes expiry
		}

		// In production, send email here
		app.InfoLog.Printf("Password reset code for %s: %s", req.Email, code)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ResetPasswordHandler completes password reset process
func (app *Config) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Code == "" || req.Password == "" {
		http.Error(w, "Email, code, and new password are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
		return
	}

	// Check if reset code exists and is valid
	codeInfo, exists := resetCodes[req.Email]
	if !exists {
		http.Error(w, "Invalid or expired reset code", http.StatusBadRequest)
		return
	}

	if codeInfo.Code != req.Code {
		http.Error(w, "Invalid reset code", http.StatusBadRequest)
		return
	}

	if time.Now().After(codeInfo.ExpiresAt) {
		delete(resetCodes, req.Email)
		http.Error(w, "Reset code has expired", http.StatusBadRequest)
		return
	}

	// Reset password
	err := app.Models.User.ResetPassword(codeInfo.UserID, req.Password)
	if err != nil {
		app.ErrorLog.Printf("Error resetting password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Remove used code
	delete(resetCodes, req.Email)

	// Create response
	response := ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// AuthMiddleware is now handled by the middleware package

// Helper functions

func generateResetCode() string {
	rand.Seed(time.Now().UnixNano())
	return strconv.Itoa(rand.Intn(900000) + 100000) // 6-digit code
}

// User Profile Handlers
func (app *Config) GetUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	user, err := app.Models.User.GetOne(claims.UserID)
	if err != nil {
		app.ErrorLog.Printf("Error getting user profile: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// GoogleOAuthLoginHandler initiates Google OAuth flow
func (app *Config) GoogleOAuthLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate OAuth state for security
	state := generateRandomState()

	// Store state in session/cookie for validation
	// In production, use secure session management

	// Redirect to Google OAuth
	googleOAuthConfig := app.getGoogleOAuthConfig()
	authURL := googleOAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// GoogleOAuthCallbackHandler handles Google OAuth callback
func (app *Config) GoogleOAuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get authorization code from query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state parameter (in production, validate against stored state)
	if state == "" {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	googleOAuthConfig := app.getGoogleOAuthConfig()
	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		app.ErrorLog.Printf("Error exchanging code for token: %v", err)
		http.Error(w, "Failed to authenticate with Google", http.StatusInternalServerError)
		return
	}

	// Get user info from Google
	service, err := googleoauth2api.NewService(context.Background(), option.WithTokenSource(googleOAuthConfig.TokenSource(context.Background(), token)))
	if err != nil {
		app.ErrorLog.Printf("Error creating Google service: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	userInfo, err := service.Userinfo.Get().Do()
	if err != nil {
		app.ErrorLog.Printf("Error getting user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Check if user exists in our database
	user, err := app.Models.User.GetByEmail(userInfo.Email)
	if err != nil {
		app.ErrorLog.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If user doesn't exist, create new user
	if user == nil {
		// Generate a random password for OAuth users
		randomPassword := generateRandomPassword()

		newUser := &data.User{
			Username: userInfo.Name,
			Email:    userInfo.Email,
			Password: randomPassword, // This will be hashed in Insert method
		}

		userID, err := app.Models.User.Insert(newUser)
		if err != nil {
			app.ErrorLog.Printf("Error creating OAuth user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Get the created user
		user, err = app.Models.User.GetOne(userID)
		if err != nil {
			app.ErrorLog.Printf("Error getting created user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Generate JWT token using the JWT service
	jwtToken, err := app.JWTService.GenerateToken(user.ID, user.Email, user.Role, nil, nil)
	if err != nil {
		app.ErrorLog.Printf("Error generating JWT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create response
	response := GoogleOAuthResponse{
		Success: true,
		Token:   jwtToken,
		User:    user,
		Message: "Google OAuth login successful",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Helper functions for OAuth
func generateRandomState() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomPassword() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func (app *Config) UpdateUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := app.Models.User.GetOne(claims.UserID)
	if err != nil {
		app.ErrorLog.Printf("Error getting user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Update fields if provided
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Email != "" {
		user.Email = req.Email
	}

	err = app.Models.User.Update(user)
	if err != nil {
		app.ErrorLog.Printf("Error updating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// DeviceAuthHandler handles device authentication and generates JWT with device info
func (app *Config) DeviceAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		DeviceID   uint   `json:"device_id"`
		MACAddress string `json:"mac_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" || req.DeviceID == 0 {
		http.Error(w, "Email, password, and device ID are required", http.StatusBadRequest)
		return
	}

	// Get user by email
	user, err := app.Models.User.GetByEmail(req.Email)
	if err != nil {
		app.ErrorLog.Printf("Error getting user by email: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Check password
	matches, err := app.Models.User.PasswordMatches(user, req.Password)
	if err != nil {
		app.ErrorLog.Printf("Error checking password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !matches {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Verify device belongs to user
	device, err := app.Models.Device.GetOne(req.DeviceID)
	if err != nil {
		app.ErrorLog.Printf("Error getting device: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	if device.UserID != user.ID {
		http.Error(w, "Device does not belong to user", http.StatusForbidden)
		return
	}

	// Generate JWT token with device information
	token, err := app.JWTService.GenerateToken(user.ID, user.Email, user.Role, &device.ID, &device.MACAddress)
	if err != nil {
		app.ErrorLog.Printf("Error generating JWT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create response
	response := map[string]interface{}{
		"success": true,
		"token":   token,
		"user":    user,
		"device":  device,
		"message": "Device authentication successful",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
