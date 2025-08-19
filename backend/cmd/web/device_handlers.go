package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sealhome/data"
	"sealhome/pkg/middleware"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi"
)

// Helper function to validate MAC address format
func isValidMACAddress(mac string) bool {
	// MAC address pattern: XX:XX:XX:XX:XX:XX (case insensitive)
	pattern := `^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
	matched, _ := regexp.MatchString(pattern, mac)
	return matched
}

// Device Handlers
func (app *Config) GetUserDevicesHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID

	// Get query parameters for filtering and pagination
	deviceType := r.URL.Query().Get("device_type")
	location := r.URL.Query().Get("location")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	// Parse pagination parameters
	page := 1
	limit := 10 // Default limit
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Get devices for the user
	devices, err := app.Models.Device.GetDevicesByUserID(userID)
	if err != nil {
		app.ErrorLog.Printf("Error getting user devices: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Apply filters
	var filteredDevices []*data.Device
	for _, device := range devices {
		// Filter by device type if specified
		if deviceType != "" && device.DeviceType != deviceType {
			continue
		}
		// Filter by location if specified
		if location != "" && device.Location != location {
			continue
		}
		filteredDevices = append(filteredDevices, device)
	}

	// Apply pagination
	totalDevices := len(filteredDevices)
	startIndex := (page - 1) * limit
	endIndex := startIndex + limit

	if startIndex >= totalDevices {
		// Return empty result if page is out of range
		response := map[string]interface{}{
			"devices": []*data.Device{},
			"pagination": map[string]interface{}{
				"page":        page,
				"limit":       limit,
				"total":       totalDevices,
				"total_pages": (totalDevices + limit - 1) / limit,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	if endIndex > totalDevices {
		endIndex = totalDevices
	}

	paginatedDevices := filteredDevices[startIndex:endIndex]

	// Create response with pagination info
	response := map[string]interface{}{
		"devices": paginatedDevices,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       totalDevices,
			"total_pages": (totalDevices + limit - 1) / limit,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *Config) AddDeviceHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID

	var req struct {
		DeviceType string `json:"device_type"`
		DeviceName string `json:"device_name"`
		Location   string `json:"location"`
		MACAddress string `json:"mac_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.DeviceType == "" || req.DeviceName == "" || req.Location == "" || req.MACAddress == "" {
		http.Error(w, "Device type, device name, location, and MAC address are required", http.StatusBadRequest)
		return
	}

	// Validate MAC address format
	if !isValidMACAddress(req.MACAddress) {
		http.Error(w, "Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX", http.StatusBadRequest)
		return
	}

	// Normalize MAC address to uppercase with colons
	req.MACAddress = strings.ToUpper(strings.ReplaceAll(req.MACAddress, "-", ":"))

	device := &data.Device{
		DeviceType: req.DeviceType,
		DeviceName: req.DeviceName,
		Location:   req.Location,
		MACAddress: req.MACAddress,
		UserID:     userID,
	}

	err := app.Models.Device.AssignDevice(userID, device)
	if err != nil {
		app.ErrorLog.Printf("Error adding device: %v", err)

		// Handle specific error cases
		if strings.Contains(err.Error(), "MAC address already exists") {
			http.Error(w, "A device with this MAC address already exists", http.StatusConflict)
			return
		}

		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(device)
}

func (app *Config) GetDeviceHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID
	deviceIDStr := chi.URLParam(r, "deviceID")

	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	device, err := app.Models.Device.GetOne(uint(deviceID))
	if err != nil {
		app.ErrorLog.Printf("Error getting device: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Check if device belongs to user
	if device.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(device)
}

func (app *Config) UpdateDeviceHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID
	deviceIDStr := chi.URLParam(r, "deviceID")

	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	device, err := app.Models.Device.GetOne(uint(deviceID))
	if err != nil {
		app.ErrorLog.Printf("Error getting device: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Check if device belongs to user
	if device.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	var req struct {
		DeviceType string `json:"device_type"`
		DeviceName string `json:"device_name"`
		Location   string `json:"location"`
		MACAddress string `json:"mac_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate MAC address format if provided
	if req.MACAddress != "" && !isValidMACAddress(req.MACAddress) {
		http.Error(w, "Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX", http.StatusBadRequest)
		return
	}

	// Update fields if provided
	if req.DeviceType != "" {
		device.DeviceType = req.DeviceType
	}
	if req.DeviceName != "" {
		device.DeviceName = req.DeviceName
	}
	if req.Location != "" {
		device.Location = req.Location
	}
	if req.MACAddress != "" {
		// Normalize MAC address to uppercase with colons
		device.MACAddress = strings.ToUpper(strings.ReplaceAll(req.MACAddress, "-", ":"))
	}

	// For now, we'll use a simple update approach
	// In a real app, you'd want to add an Update method to the DeviceInterface
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(device)
}

func (app *Config) DeleteDeviceHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID
	deviceIDStr := chi.URLParam(r, "deviceID")

	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid device ID", http.StatusBadRequest)
		return
	}

	device, err := app.Models.Device.GetOne(uint(deviceID))
	if err != nil {
		app.ErrorLog.Printf("Error getting device: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if device == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	// Check if device belongs to user
	if device.UserID != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// For now, we'll return success
	// In a real app, you'd want to add a Delete method to the DeviceInterface
	w.WriteHeader(http.StatusNoContent)
}

// GetUserDeviceStatsHandler returns statistics about the user's devices
func (app *Config) GetUserDeviceStatsHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	userID := claims.UserID

	// Get all devices for the user
	devices, err := app.Models.Device.GetDevicesByUserID(userID)
	if err != nil {
		app.ErrorLog.Printf("Error getting user device stats: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Calculate statistics
	stats := map[string]interface{}{
		"total_devices": len(devices),
		"device_types":  make(map[string]int),
		"locations":     make(map[string]int),
	}

	// Count devices by type and location
	for _, device := range devices {
		// Count by device type
		stats["device_types"].(map[string]int)[device.DeviceType]++

		// Count by location
		stats["locations"].(map[string]int)[device.Location]++
	}

	// Add recent devices (last 7 days)
	recentDevices := 0
	weekAgo := time.Now().AddDate(0, 0, -7)
	for _, device := range devices {
		if device.CreatedAt.After(weekAgo) {
			recentDevices++
		}
	}
	stats["recent_devices"] = recentDevices

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
