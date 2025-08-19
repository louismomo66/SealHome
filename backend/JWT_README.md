# JWT Authentication Implementation

This document describes the JWT (JSON Web Token) authentication system implemented in the SealHome backend.

## Features

- **JWT Token Generation**: Creates tokens with user email, user ID, role, and optional device information
- **Token Expiration**: Configurable expiration time (default: 48 hours)
- **Device Authentication**: Special tokens that include device ID and MAC address
- **Middleware Protection**: Routes can be protected with authentication middleware
- **Role-based Access**: Support for role-based authorization

## Configuration

### Environment Variables

Create a `.env` file in the backend directory with the following variables:

```env
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRATION_HOURS=48

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=sealhome
DB_SSLMODE=disable

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost
```

## JWT Token Structure

### Standard User Token
```json
{
  "user_id": 123,
  "email": "user@example.com",
  "role": "user",
  "exp": 1640995200,
  "iat": 1640908800,
  "nbf": 1640908800,
  "iss": "sealhome",
  "sub": "123"
}
```

### Device Token (includes device information)
```json
{
  "user_id": 123,
  "email": "user@example.com",
  "role": "user",
  "device_id": 456,
  "mac_address": "AA:BB:CC:DD:EE:FF",
  "exp": 1640995200,
  "iat": 1640908800,
  "nbf": 1640908800,
  "iss": "sealhome",
  "sub": "123"
}
```

## API Endpoints

### Authentication Endpoints

#### 1. User Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "user@example.com",
    "role": "user"
  },
  "message": "Login successful"
}
```

#### 2. Device Authentication
```http
POST /api/auth/device
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123",
  "device_id": 456,
  "mac_address": "AA:BB:CC:DD:EE:FF"
}
```

Response:
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 123,
    "username": "john_doe",
    "email": "user@example.com",
    "role": "user"
  },
  "device": {
    "id": 456,
    "device_type": "sensor",
    "device_name": "Temperature Sensor",
    "mac_address": "AA:BB:CC:DD:EE:FF"
  },
  "message": "Device authentication successful"
}
```

### Protected Endpoints

All protected endpoints require the `Authorization` header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### User Profile
```http
GET /api/users/profile
PUT /api/users/profile
```

#### Device Management
```http
GET /api/devices
POST /api/devices
GET /api/devices/{deviceID}
PUT /api/devices/{deviceID}
DELETE /api/devices/{deviceID}
GET /api/devices/stats
```

## Middleware Usage

### Authentication Middleware

The authentication middleware validates JWT tokens and extracts user information:

```go
// Apply to routes that require authentication
r.Use(authmiddleware.AuthMiddleware(app.JWTService))
```

### Optional Authentication Middleware

For routes that can work with or without authentication:

```go
// Apply to routes that optionally use authentication
r.Use(authmiddleware.OptionalAuthMiddleware(app.JWTService))
```

### Role-based Authorization

For routes that require specific roles:

```go
// Apply after authentication middleware
r.Use(authmiddleware.RoleMiddleware("admin", "moderator"))
```

## Accessing User Information in Handlers

```go
func (app *Config) MyHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.GetUserFromContext(r.Context())
    if !ok {
        http.Error(w, "User not authenticated", http.StatusUnauthorized)
        return
    }
    
    // Access user information
    userID := claims.UserID
    email := claims.Email
    role := claims.Role
    deviceID := claims.DeviceID
    macAddress := claims.MACAddress
    
    // Your handler logic here
}
```

## Security Considerations

1. **JWT Secret**: Use a strong, unique secret key in production
2. **Token Expiration**: Set appropriate expiration times
3. **HTTPS**: Always use HTTPS in production
4. **Token Storage**: Store tokens securely on the client side
5. **Token Refresh**: Implement token refresh mechanism for long-lived sessions

## Error Responses

### Authentication Errors
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Insufficient permissions

### Common Error Response Format
```json
{
  "error": "Invalid or expired token",
  "status": 401
}
```

## Testing

You can test the JWT implementation using curl:

```bash
# Login and get token
curl -X POST http://localhost:9004/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Use token for protected endpoint
curl -X GET http://localhost:9004/api/users/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
