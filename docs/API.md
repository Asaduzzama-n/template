# API Reference

Complete API reference for all endpoints in the Express-Craft backend.

## Base URL
```
Development: http://localhost:5000/api/v1
Production: https://api.yourdomain.com/api/v1
```

## Authentication
Most endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

---

## Health & Monitoring

### Health Check
Check if the server is running.

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00.000Z",
  "uptime": 86400
}
```

### Ready Check
Check if the server is ready to accept requests.

```http
GET /ready
```

**Response:**
```json
{
  "status": "ready",
  "timestamp": "2024-01-15T12:00:00.000Z"
}
```

---

## Cache Management

> **Note:** All cache endpoints require Admin authentication.

### Get Cache Statistics
```http
GET /api/v1/cache/stats
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "message": "Cache statistics retrieved successfully",
  "data": {
    "totalHits": 1500,
    "totalMisses": 300,
    "totalRequests": 1800,
    "hitRate": "83.33%",
    "lastReset": "2024-01-15T00:00:00.000Z"
  }
}
```

### Reset Cache Statistics
```http
POST /api/v1/cache/stats/reset
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "message": "Cache statistics reset successfully",
  "data": null
}
```

### Get All Cached Keys
```http
GET /api/v1/cache/keys
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "message": "Cached keys retrieved successfully",
  "data": {
    "count": 42,
    "keys": [
      "cache:query:users:p1:l10:screatedAt:odesc",
      "cache:query:products:p1:l20:screatedAt:odesc",
      "..."
    ]
  }
}
```

### Clear All Cache
```http
DELETE /api/v1/cache/clear
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "message": "Cleared 42 cached entries",
  "data": {
    "deletedCount": 42
  }
}
```

### Redis Health Check
```http
GET /api/v1/cache/redis/health
```

**Response (Healthy):**
```json
{
  "success": true,
  "message": "Redis is healthy",
  "data": {
    "connected": true,
    "healthy": true
  }
}
```

**Response (Unhealthy):**
```json
{
  "success": false,
  "message": "Redis is unavailable",
  "data": {
    "connected": false,
    "healthy": false
  }
}
```

---

## Authentication

### Register
```http
POST /api/v1/auth/register
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "An OTP has been sent to your email",
  "data": null
}
```

### Login
```http
POST /api/v1/auth/login
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

### Verify OTP
```http
POST /api/v1/auth/verify-account
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "otp": "123456"
}
```

### Resend OTP
```http
POST /api/v1/auth/resend-otp
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "type": "createAccount"
}
```

### Forgot Password
```http
POST /api/v1/auth/forgot-password
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

### Reset Password
```http
POST /api/v1/auth/reset-password
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "john@example.com",
  "otp": "123456",
  "newPassword": "NewSecurePassword123!",
  "confirmPassword": "NewSecurePassword123!"
}
```

### Change Password
```http
POST /api/v1/auth/change-password
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewPassword123!"
}
```

### Refresh Token
```http
POST /api/v1/auth/refresh-token
Content-Type: application/json
```

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## User

### Update Profile
```http
PATCH /api/v1/user/profile
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

**Request Body (Form Data):**
```
name: John Doe Updated
image: [file]
```

---

## Notifications

### Get Notifications
```http
GET /api/v1/notifications?page=1&limit=10
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "message": "Notifications retrieved successfully",
  "data": {
    "meta": {
      "page": 1,
      "limit": 10,
      "total": 25,
      "totalPages": 3
    },
    "data": [
      {
        "_id": "notification123",
        "from": {
          "_id": "user456",
          "name": "Jane Doe",
          "profile": "https://..."
        },
        "title": "New Message",
        "body": "You have a new message",
        "isRead": false,
        "createdAt": "2024-01-15T12:00:00.000Z"
      }
    ]
  }
}
```

### Mark Notification as Read
```http
PATCH /api/v1/notifications/:id/read
Authorization: Bearer <token>
```

### Mark All as Read
```http
PATCH /api/v1/notifications/read-all
Authorization: Bearer <token>
```

---

## Error Responses

### Rate Limited
```json
{
  "success": false,
  "message": "Too many requests, please try again later.",
  "retryAfter": 30
}
```
**Status:** `429 Too Many Requests`

### Unauthorized
```json
{
  "success": false,
  "message": "You are not authorized"
}
```
**Status:** `401 Unauthorized`

### Validation Error
```json
{
  "success": false,
  "message": "Validation failed",
  "errorMessages": [
    {
      "path": "email",
      "message": "Invalid email format"
    }
  ]
}
```
**Status:** `400 Bad Request`

### Not Found
```json
{
  "success": false,
  "message": "Resource not found"
}
```
**Status:** `404 Not Found`

### Server Error
```json
{
  "success": false,
  "message": "Internal server error"
}
```
**Status:** `500 Internal Server Error`

---

## Response Headers

### Rate Limit Headers
All API responses include rate limiting information:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705329600
```

### Correlation ID
All responses include a correlation ID for tracing:
```
X-Correlation-ID: abc123-def456-ghi789
```

---

## WebSocket Events

### Connection
```javascript
const socket = io('https://api.yourdomain.com', {
  auth: { token: 'your-jwt-token' }
})
```

### Events (Client → Server)
| Event | Description |
|-------|-------------|
| `logout` | Force logout from all devices |

### Events (Server → Client)
| Event | Payload | Description |
|-------|---------|-------------|
| `notification` | `{ _id, from, title, body, isRead, createdAt }` | New notification |
| `system-update` | `{ message }` | System announcements |
