# Sealhome Backend

A Go-based backend service for the Sealhome application with JWT authentication and Google OAuth integration.

## Features

- JWT-based authentication
- Google OAuth integration
- User management with phone number support
- Device management
- Password reset functionality

## Setup

### Prerequisites

- Go 1.23.3 or higher
- PostgreSQL database
- Google OAuth credentials

### Environment Variables

Create a `.env` file in the backend directory with the following variables:

```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=sealhome

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Google OAuth Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/google/callback

# Server Configuration
PORT=8080
```

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" and create an OAuth 2.0 Client ID
5. Set the authorized redirect URI to: `http://localhost:8080/api/auth/google/callback`
6. Copy the Client ID and Client Secret to your environment variables

### Installation

1. Install dependencies:
```bash
go mod tidy
```

2. Set up the database:
```bash
# Create the database
createdb sealhome

# Run migrations (if using GORM auto-migration, this happens automatically)
```

3. Run the application:
```bash
go run cmd/web/*.go
```

## API Endpoints

### Authentication

- `POST /api/auth/signup` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/google` - Initiate Google OAuth
- `GET /api/auth/google/callback` - Google OAuth callback
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password

### User Management

- `GET /api/users/profile` - Get user profile (authenticated)
- `PUT /api/users/profile` - Update user profile (authenticated)

### Device Management

- `GET /api/devices` - Get user devices with pagination and filtering (authenticated)
- `GET /api/devices/stats` - Get device statistics for the user (authenticated)
- `POST /api/devices` - Add new device (authenticated)
- `GET /api/devices/{deviceID}` - Get specific device (authenticated)
- `PUT /api/devices/{deviceID}` - Update device (authenticated)
- `DELETE /api/devices/{deviceID}` - Delete device (authenticated)

## Request/Response Examples

### Signup Request
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "password": "securepassword123"
}
```

### Login Request
```json
{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

### Login Response
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  },
  "message": "Login successful"
}
```

### Device Listing Response
```json
{
  "devices": [
    {
      "id": 1,
      "device_type": "camera",
      "device_name": "Front Door Camera",
      "location": "Front Door",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "user_id": 1,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    },
    {
      "id": 2,
      "device_type": "sensor",
      "device_name": "Motion Sensor",
      "location": "Living Room",
      "mac_address": "11:22:33:44:55:66",
      "user_id": 1,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 2,
    "total_pages": 1
  }
}
```

### Device Statistics Response
```json
{
  "total_devices": 5,
  "device_types": {
    "camera": 2,
    "sensor": 2,
    "lock": 1
  },
  "locations": {
    "Front Door": 2,
    "Living Room": 2,
    "Back Door": 1
  },
  "recent_devices": 1
}
```

## Security Notes

- Change the JWT secret in production
- Use HTTPS in production
- Store OAuth credentials securely
- Implement proper session management for OAuth state validation
- Add rate limiting for authentication endpoints
- Use secure password hashing (already implemented with bcrypt)
