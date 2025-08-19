package jwt

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims structure
type Claims struct {
	UserID     uint   `json:"user_id"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	DeviceID   uint   `json:"device_id,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations
type JWTService struct {
	secretKey []byte
}

// NewJWTService creates a new JWT service instance
func NewJWTService() (*JWTService, error) {
	secretKey := os.Getenv("JWT_SECRET")
	if secretKey == "" {
		return nil, errors.New("JWT_SECRET environment variable is not set")
	}

	return &JWTService{
		secretKey: []byte(secretKey),
	}, nil
}

// GenerateToken creates a new JWT token with the specified claims
func (j *JWTService) GenerateToken(userID uint, email, role string, deviceID *uint, macAddress *string) (string, error) {
	// Get expiration hours from environment variable, default to 48 hours
	expHours := 48
	if expStr := os.Getenv("JWT_EXPIRATION_HOURS"); expStr != "" {
		if parsed, err := strconv.Atoi(expStr); err == nil {
			expHours = parsed
		}
	}

	now := time.Now()
	expiration := now.Add(time.Duration(expHours) * time.Hour)

	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "sealhome",
			Subject:   fmt.Sprintf("%d", userID),
		},
	}

	// Add device information if provided
	if deviceID != nil {
		claims.DeviceID = *deviceID
	}
	if macAddress != nil {
		claims.MACAddress = *macAddress
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// ValidateToken validates and parses a JWT token
func (j *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken creates a new token with the same claims but extended expiration
func (j *JWTService) RefreshToken(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Create new token with extended expiration
	return j.GenerateToken(claims.UserID, claims.Email, claims.Role, &claims.DeviceID, &claims.MACAddress)
}
