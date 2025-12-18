# Express-Craft Production Infrastructure Documentation

This documentation covers all the production-ready features implemented in the Express-Craft backend template.

## Table of Contents

1. [Logging System](#1-logging-system)
2. [Redis Adapter](#2-redis-adapter)
3. [Query Caching](#3-query-caching)
4. [Rate Limiting](#4-rate-limiting)
5. [Background Jobs (BullMQ)](#5-background-jobs-bullmq)
6. [Socket.IO with Redis](#6-socketio-with-redis)
7. [Security Middleware](#7-security-middleware)
8. [Nginx Configuration](#8-nginx-configuration)
9. [Docker Deployment](#9-docker-deployment)
10. [CI/CD Pipeline](#10-cicd-pipeline)

---

## 1. Logging System

### Overview
Production-ready structured logging with Winston, featuring JSON output for production, pretty printing for development, and automatic sensitive data redaction.

### Features
- **Structured JSON logs** in production for log aggregators (ELK, CloudWatch, Datadog)
- **Pretty formatted logs** in development with colors
- **Environment-based log levels**
- **Sensitive data redaction** (passwords, tokens)
- **Error stack traces** properly formatted
- **Correlation IDs** for request tracing

### Configuration
```env
# .env
LOG_LEVEL=info  # Options: debug, info, warn, error
```

### Usage Examples

#### Basic Logging
```typescript
import { logger } from './shared/logger'

// Info level
logger.info('User logged in successfully', { 
  userId: '123', 
  ip: '192.168.1.1' 
})

// Warning level
logger.warn('Rate limit approaching', { 
  userId: '123', 
  currentCount: 90, 
  limit: 100 
})

// Error level with stack trace
logger.error('Database connection failed', { 
  error: new Error('Connection refused'),
  host: 'localhost',
  port: 27017
})

// Debug level (only shown when LOG_LEVEL=debug)
logger.debug('Processing request', { 
  body: req.body, 
  headers: req.headers 
})
```

#### Request-scoped Logging with Correlation ID
```typescript
import { withCorrelationId } from './shared/logger'

// In your service/controller
const log = withCorrelationId(req.correlationId)

log.info('Starting payment processing')
log.info('Payment completed', { transactionId: 'txn_123' })
// All logs will include the same correlationId for tracing
```

#### Log Output Examples

**Development (pretty format):**
```
12:30:45 info: [abc-123-def] User logged in successfully
{
  "userId": "123",
  "ip": "192.168.1.1"
}
```

**Production (JSON format):**
```json
{
  "timestamp": "2024-01-15 12:30:45.123",
  "level": "info",
  "message": "User logged in successfully",
  "correlationId": "abc-123-def",
  "userId": "123",
  "ip": "192.168.1.1",
  "service": "express-craft",
  "environment": "production"
}
```

---

## 2. Redis Adapter

### Overview
Centralized Redis connection management with connection pooling, Pub/Sub support for Socket.IO, and graceful shutdown handling.

### Features
- **Single connection pool** reused across all modules
- **Pub/Sub clients** for Socket.IO adapter
- **Health checks**
- **Automatic reconnection** with retry logic
- **Graceful shutdown**

### Configuration
```env
# .env
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-secure-password  # Optional for local dev
```

### Usage Examples

#### Getting Redis Client
```typescript
import { getRedisClient } from './adapters/redisAdapter'

// Get the Redis client
const redis = getRedisClient()

// Basic operations
await redis.set('key', 'value')
const value = await redis.get('key')

// With expiration (TTL in seconds)
await redis.setex('session:123', 3600, JSON.stringify(sessionData))

// Hash operations
await redis.hset('user:123', 'name', 'John', 'email', 'john@example.com')
const user = await redis.hgetall('user:123')

// List operations
await redis.lpush('queue:emails', JSON.stringify(emailJob))
const job = await redis.rpop('queue:emails')
```

#### Health Check
```typescript
import { redisAdapter } from './adapters/redisAdapter'

// Check if Redis is healthy
const isHealthy = await redisAdapter.healthCheck()
console.log('Redis healthy:', isHealthy) // true or false

// Check connection status
console.log('Redis connected:', redisAdapter.isConnected)
```

#### Pub/Sub for Real-time Features
```typescript
import { getRedisPublisher, getRedisSubscriber } from './adapters/redisAdapter'

// Publisher
const publisher = getRedisPublisher()
await publisher.publish('channel:updates', JSON.stringify({ type: 'NEW_MESSAGE' }))

// Subscriber
const subscriber = getRedisSubscriber()
subscriber.subscribe('channel:updates')
subscriber.on('message', (channel, message) => {
  console.log(`Received on ${channel}:`, JSON.parse(message))
})
```

---

## 3. Query Caching

### Overview
Redis-based query caching with pagination support, automatic key generation, and statistics tracking.

### Features
- **Pagination-aware cache keys**
- **Automatic serialization/deserialization**
- **TTL presets** (SHORT, MEDIUM, LONG, VERY_LONG)
- **Pattern-based invalidation**
- **Cache statistics** (hits, misses, hit rate)

### API Endpoints
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/cache/stats` | Get cache statistics | Admin |
| POST | `/api/v1/cache/stats/reset` | Reset statistics | Admin |
| GET | `/api/v1/cache/keys` | List all cached keys | Admin |
| DELETE | `/api/v1/cache/clear` | Clear all cache | Admin |
| GET | `/api/v1/cache/redis/health` | Redis health check | Public |

### Usage Examples

#### Basic Caching
```typescript
import { cacheHelper, CACHE_TTL } from './helpers/cacheHelper'

// Set cache
await cacheHelper.setCache('user:123', userData, CACHE_TTL.MEDIUM)

// Get cache
const cachedUser = await cacheHelper.getCache<User>('user:123')
if (cachedUser) {
  return cachedUser
}

// Delete cache
await cacheHelper.deleteCache('user:123')
```

#### Pagination-Aware Caching
```typescript
import { cacheHelper, CACHE_TTL } from './helpers/cacheHelper'

// In your service
const getUsers = async (pagination: { page: number; limit: number; sortBy: string }) => {
  // Build a cache key that includes pagination params
  const cacheKey = cacheHelper.buildCacheKey(
    'users',           // entity name
    undefined,         // identifier (optional)
    pagination         // pagination params
  )
  // Key format: cache:query:users:p1:l10:screatedAt:odesc

  // Use withCache for automatic cache handling
  return cacheHelper.withCache(cacheKey, CACHE_TTL.MEDIUM, async () => {
    // This only runs if cache misses
    const users = await User.find()
      .skip((pagination.page - 1) * pagination.limit)
      .limit(pagination.limit)
      .sort({ [pagination.sortBy]: -1 })
    
    const total = await User.countDocuments()
    
    return {
      data: users,
      meta: { page: pagination.page, limit: pagination.limit, total }
    }
  })
}
```

#### Caching with Filters
```typescript
const getProducts = async (filters: { category: string; minPrice: number }) => {
  const cacheKey = cacheHelper.buildCacheKey(
    'products',
    undefined,
    { page: 1, limit: 20 },
    filters  // Additional filters
  )
  // Key: cache:query:products:p1:l20:screatedAt:odesc:category:electronics_minPrice:100

  return cacheHelper.withCache(cacheKey, CACHE_TTL.SHORT, async () => {
    return Product.find({ 
      category: filters.category, 
      price: { $gte: filters.minPrice } 
    })
  })
}
```

#### Cache Invalidation
```typescript
// Invalidate single key
await cacheHelper.deleteCache('cache:query:users:123')

// Invalidate all pages of a query (pattern-based)
await cacheHelper.invalidateCachePattern('cache:query:users:*')

// Invalidate all product cache for a category
await cacheHelper.invalidateCachePattern('cache:query:products:*category:electronics*')

// Clear all cache
await cacheHelper.clearAllCache()
```

#### Monitoring Cache Stats
```typescript
// Get statistics
const stats = await cacheHelper.getCacheStats()
console.log('Cache Stats:', {
  hits: stats.hits,           // 1500
  misses: stats.misses,       // 300
  hitRate: stats.hits / (stats.hits + stats.misses) // 0.83 (83%)
})

// Reset statistics
await cacheHelper.resetCacheStats()

// Get all cached keys
const keys = await cacheHelper.getAllCacheKeys()
console.log('Cached keys:', keys)
```

---

## 4. Rate Limiting

### Overview
Redis-backed rate limiting with sliding window algorithm, supporting global API protection and endpoint-specific limits.

### Features
- **Sliding window algorithm** (smoother than fixed window)
- **Redis-backed** for distributed systems
- **Configurable** via environment variables
- **Multiple presets** for different use cases
- **Rate limit headers** in responses

### Configuration
```env
# .env
RATE_LIMIT_WINDOW_MS=60000    # 1 minute window
RATE_LIMIT_MAX_REQUESTS=100   # 100 requests per window
```

### Available Presets
| Preset | Window | Max Requests | Use Case |
|--------|--------|--------------|----------|
| `apiRateLimiter` | 1 min | 100 | General API endpoints |
| `authRateLimiter` | 15 min | 30 | Login, signup, password reset |
| `strictRateLimiter` | 1 hour | 10 | Sensitive operations |
| `userRateLimiter` | 1 min | 200 | Authenticated user-based limit |

### Usage Examples

#### Apply to Routes
```typescript
import { apiRateLimiter, authRateLimiter, strictRateLimiter } from './app/middleware/rateLimiter'

// Apply globally to all API routes
app.use('/api', apiRateLimiter)

// Apply to auth routes
router.post('/login', authRateLimiter, authController.login)
router.post('/register', authRateLimiter, authController.register)

// Apply strict limit to sensitive operations
router.post('/admin/delete-all', strictRateLimiter, adminController.deleteAll)
```

#### Custom Rate Limiter
```typescript
import { rateLimiter } from './app/middleware/rateLimiter'

// Create a custom rate limiter
const uploadRateLimiter = rateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  maxRequests: 20,          // 20 uploads per hour
  keyPrefix: 'ratelimit:upload',
})

router.post('/upload', uploadRateLimiter, uploadController.upload)
```

#### Custom Key Generator
```typescript
import { rateLimiter } from './app/middleware/rateLimiter'

// Rate limit by user ID instead of IP
const userBasedLimiter = rateLimiter({
  windowMs: 60000,
  maxRequests: 50,
  keyPrefix: 'ratelimit:user',
  keyGenerator: (req) => {
    return req.user?.authId || req.ip
  },
})
```

#### Response Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705329600
Retry-After: 30  (only when limit exceeded)
```

---

## 5. Background Jobs (BullMQ)

### Overview
Redis-backed job queue for handling background tasks like sending emails, notifications, and other async operations.

### Features
- **Email queue** with rate limiting (respects email provider limits)
- **Notification queue** for push notifications
- **Retry logic** with exponential backoff
- **Failed job retention** for debugging
- **Graceful shutdown**

### Queue Configuration
| Queue | Concurrency | Rate Limit | Use Case |
|-------|-------------|------------|----------|
| `email-queue` | 5 | 100/min | Sending emails |
| `notification-queue` | 10 | None | Push notifications |
| `push-notification-queue` | 20 | None | Mobile push |

### Usage Examples

#### Queue an Email
```typescript
import { emailHelper } from './helpers/emailHelper'

// Queue email (non-blocking, returns immediately)
const jobId = await emailHelper.queueEmail({
  to: 'user@example.com',
  subject: 'Welcome!',
  html: '<h1>Welcome to our platform</h1>'
})
console.log('Email queued with job ID:', jobId)

// Queue OTP email with high priority
await emailHelper.queueOtpEmail({
  to: 'user@example.com',
  subject: 'Your OTP Code',
  html: '<p>Your OTP is: <strong>123456</strong></p>'
})

// Queue with delay (send in 5 minutes)
await emailHelper.queueEmail(
  { to: 'user@example.com', subject: 'Reminder', html: '...' },
  { delay: 5 * 60 * 1000 }
)
```

#### Queue a Notification
```typescript
import { queueNotification } from './helpers/notificationHelper'

// Queue notification (creates DB record + socket emit + push notification)
await queueNotification(
  { authId: 'sender123', name: 'John' },  // from
  'recipient456',                          // to (userId)
  'New Message',                           // title
  'You have a new message from John',      // body
  'fcm-device-token',                      // optional device token
  { messageId: 'msg123' }                  // optional extra data
)
```

#### Direct Job Management
```typescript
import { addJob, getQueue, QUEUE_NAMES, JOB_TYPES } from './queues'

// Add a job directly
const job = await addJob(
  QUEUE_NAMES.EMAIL,
  JOB_TYPES.EMAIL.SEND_EMAIL,
  { to: 'user@example.com', subject: 'Test', html: '<p>Test</p>' },
  { priority: 1, attempts: 5 }
)

// Get queue for monitoring
const emailQueue = getQueue(QUEUE_NAMES.EMAIL)

// Get job counts
const counts = await emailQueue.getJobCounts()
console.log('Queue status:', counts)
// { waiting: 5, active: 2, completed: 100, failed: 3 }
```

---

## 6. Socket.IO with Redis

### Overview
Scalable WebSocket implementation using Redis for user-to-socket mapping, enabling horizontal scaling across multiple server instances.

### Features
- **Redis-backed socket mappings** for horizontal scaling
- **Multi-device support** (one user, multiple connections)
- **Clean disconnect handling**
- **User-targeted emissions**
- **Socket.IO Redis adapter** for pub/sub

### Usage Examples

#### Emit to Specific User
```typescript
import { emitToUser, emitToUsers, broadcast } from './helpers/socketHelper'

// Emit to a specific user (all their connected devices)
await emitToUser('user123', 'notification', {
  title: 'New Message',
  body: 'You have a new message'
})

// Emit to multiple users
await emitToUsers(['user123', 'user456'], 'announcement', {
  message: 'New feature available!'
})

// Broadcast to everyone
broadcast('system-update', {
  message: 'System will restart in 5 minutes'
})
```

#### Check User Online Status
```typescript
import { socketRedis } from './helpers/socketRedis'

// Check if user is online
const isOnline = await socketRedis.isUserOnline('user123')
console.log('User online:', isOnline)

// Get all online users
const onlineUsers = await socketRedis.getOnlineUsers()
console.log('Online users:', onlineUsers)

// Get all sockets for a user
const sockets = await socketRedis.getUserSockets('user123')
console.log('User has', sockets.length, 'connections')
```

#### Clear User Sessions (Logout)
```typescript
import { socketRedis } from './helpers/socketRedis'

// Clear all sockets on logout (force disconnect from all devices)
await socketRedis.clearUserSockets('user123')
```

#### Client-Side Connection
```typescript
// Frontend code
import { io } from 'socket.io-client'

const socket = io('https://api.yourdomain.com', {
  auth: {
    token: 'your-jwt-token'  // Required for authentication
  }
})

socket.on('notification', (data) => {
  console.log('New notification:', data)
})

socket.on('connect', () => {
  console.log('Connected with ID:', socket.id)
})

socket.on('disconnect', (reason) => {
  console.log('Disconnected:', reason)
})
```

---

## 7. Security Middleware

### Overview
Comprehensive security middleware stack including Helmet for headers, NoSQL injection prevention, and request validation.

### Security Layers
1. **Helmet** - Security headers (HSTS, CSP, X-Frame-Options, etc.)
2. **Suspicious UA Blocking** - Blocks known attack tools
3. **Content-Type Validation** - Validates request body types
4. **NoSQL Injection Prevention** - Sanitizes `$` and `.` from input
5. **Parameter Pollution Prevention** - Removes duplicate params

### Usage Examples

#### Default Security (Already Applied in app.ts)
```typescript
// These are already applied in app.ts
import { 
  securityHeaders, 
  blockSuspiciousUserAgents,
  validateContentType,
  sanitizeInput,
  preventParameterPollution 
} from './app/middleware/security'

app.use(securityHeaders)
app.use(blockSuspiciousUserAgents)
app.use(validateContentType)
app.use(sanitizeInput)
app.use(preventParameterPollution)
```

#### CORS Configuration
```typescript
// Configured in app.ts
const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? process.env.ALLOWED_ORIGINS?.split(',')  // ['https://app.example.com']
    : '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID'],
}
```

#### Environment Variables
```env
# Production CORS - comma-separated list
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

### Security Headers Applied
| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Force HTTPS |
| `X-Frame-Options` | `SAMEORIGIN` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | XSS protection |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Control referrer |
| `Content-Security-Policy` | `default-src 'self'; ...` | Prevent XSS/injection |

---

## 8. Nginx Configuration

### Overview
Production-ready Nginx reverse proxy with SSL, rate limiting, security headers, and WebSocket support.

### Files
- `nginx/nginx.conf` - Production configuration with SSL
- `nginx/nginx.dev.conf` - Development configuration (no SSL)
- `nginx/proxy_params.conf` - Shared proxy settings

### Features
- **SSL/TLS 1.2-1.3** only (modern security)
- **HSTS preload** ready
- **Gzip compression**
- **Rate limiting** at edge
- **WebSocket support**
- **Static file caching**
- **Security headers**

### SSL Setup with Let's Encrypt
```bash
# 1. Create SSL directory
mkdir -p nginx/ssl

# 2. Start nginx without SSL first (for ACME challenge)
docker compose up -d nginx

# 3. Obtain certificate
docker compose run --rm certbot certonly \
  --webroot \
  --webroot-path=/var/www/certbot \
  --email your@email.com \
  --agree-tos \
  --no-eff-email \
  -d yourdomain.com \
  -d www.yourdomain.com

# 4. Restart nginx with SSL
docker compose restart nginx
```

### Custom Rate Limits
```nginx
# In nginx/nginx.conf

# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;

# Apply to locations
location /api/v1/auth {
    limit_req zone=auth_limit burst=5 nodelay;
    # ...
}
```

---

## 9. Docker Deployment

### Overview
Multi-stage Dockerfile with PM2 for process management, and Docker Compose for orchestration.

### Files
- `Dockerfile` - Multi-stage production build
- `docker-compose.yml` - Production with Nginx + SSL
- `docker-compose.dev.yml` - Development setup
- `ecosystem.config.js` - PM2 configuration
- `.dockerignore` - Build context exclusions

### Quick Start

#### Development
```bash
# Start all services
docker compose -f docker-compose.dev.yml up -d

# View logs
docker compose -f docker-compose.dev.yml logs -f

# Stop
docker compose -f docker-compose.dev.yml down
```

#### Production
```bash
# Build and start
docker compose up -d --build

# View logs
docker compose logs -f

# Scale app (if not using PM2 cluster)
docker compose up -d --scale app=3

# Stop
docker compose down
```

### PM2 Commands (Inside Container)
```bash
# View process status
docker compose exec app pm2 status

# View logs
docker compose exec app pm2 logs

# Restart app
docker compose exec app pm2 restart express-craft

# Monitor
docker compose exec app pm2 monit
```

### Environment Variables
```env
# Required
DATABASE_URL=mongodb://mongo:27017/your-db
JWT_SECRET=your-very-long-secret-key-here
JWT_REFRESH_SECRET=your-refresh-secret-key
REDIS_URL=redis://redis:6379
REDIS_PASSWORD=your-redis-password

# Optional
LOG_LEVEL=info
RATE_LIMIT_MAX_REQUESTS=100
ALLOWED_ORIGINS=https://yourdomain.com
```

---

## 10. CI/CD Pipeline

### Overview
GitHub Actions workflow for automated testing, Docker image building, and deployment.

### Pipeline Stages
1. **Test** - Lint, type check, unit tests
2. **Build** - Docker image build and push to GHCR
3. **Deploy** - SSH to server and deploy

### Required GitHub Secrets
| Secret | Description | Example |
|--------|-------------|---------|
| `SSH_HOST` | Server IP/hostname | `123.45.67.89` |
| `SSH_USER` | SSH username | `deploy` |
| `SSH_PRIVATE_KEY` | SSH private key | `-----BEGIN...` |
| `SSH_PORT` | SSH port (optional) | `22` |
| `DEPLOY_PATH` | Server deploy path | `/opt/app` |
| `APP_URL` | App URL for health check | `https://api.example.com` |

### Setting Up Deployment Server
```bash
# On your server

# 1. Install Docker
curl -fsSL https://get.docker.com | sh

# 2. Create deploy user
useradd -m -s /bin/bash deploy
usermod -aG docker deploy

# 3. Create deployment directory
mkdir -p /opt/app
chown deploy:deploy /opt/app

# 4. Add deploy user's SSH key
mkdir -p /home/deploy/.ssh
# Add your GitHub Actions public key to authorized_keys
```

### Manual Deployment Trigger
```bash
# Force deploy from GitHub Actions
git commit --allow-empty -m "Deploy to production"
git push origin main
```

### Rollback
```bash
# On server, pull previous image
docker pull ghcr.io/your-org/your-repo:previous-tag
docker compose down
docker compose up -d
```

---

## Quick Reference

### Environment Variables Summary
```env
# Server
NODE_ENV=production
PORT=5000

# Database
DATABASE_URL=mongodb://localhost:27017/your-db

# JWT
JWT_SECRET=super-secret-key-at-least-32-chars
JWT_REFRESH_SECRET=another-secret-key
JWT_EXPIRE_IN=1d
JWT_REFRESH_EXPIRE_IN=7d

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your-redis-password

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=100

# Logging
LOG_LEVEL=info

# CORS
ALLOWED_ORIGINS=https://yourdomain.com

# Email
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your-email
EMAIL_PASS=your-password
EMAIL_FROM=noreply@example.com
```

### Common Commands
```bash
# Development
npm run dev

# Production with Docker
docker compose up -d

# View logs
docker compose logs -f app

# Check PM2 status
docker compose exec app pm2 status

# Clear cache
curl -X DELETE localhost:5000/api/v1/cache/clear -H "Authorization: Bearer <admin-token>"

# Check health
curl localhost:5000/health
```
