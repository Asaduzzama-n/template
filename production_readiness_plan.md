# Production-Readiness Plan: Express Template Backend

> **Scope:** Full audit of every layer — config, auth, global error handler, socket/real-time, notifications, helpers (email, JWT, push, image), middleware (file upload, request body), QueryBuilder, and server bootstrap.  
> **Goals:** Efficiency · Scalability · Security  
> **Priority Tiers:** 🔴 Critical (do first) · 🟡 High · 🟢 Standard

---

## Executive Summary

The template is architecturally sound with solid foundations (Zod validation, transaction-safe auth, brute-force protection, bcrypt OTP hashing). However, **several critical gaps** must be fixed before any production deployment:

| Area | Critical Issues Found |
|---|---|
| `app.ts` + `server.ts` | Wildcard CORS, no helmet, no rate limiter, no request size cap, no graceful DB disconnect |
| `auth middleware` | 404 on missing token (should be 401), token-not-provided silent bypass |
| `custom.auth.service.ts` | OTP expiry hardcoded 2 min, dev OTP leaked in response body |
| `socketHelper.ts` | `onlineUsers` Map in-process only (kills horizontal scaling), wildcard Socket CORS |
| `notificationHelper.ts` | Uses `global.io` (deprecated pattern), no targeted room emit |
| `socketInstances.ts` | `console.warn/error` instead of structured logger |
| `pushnotificationHelper.ts` | Firebase initialized at module load-time (crashes if base64 missing) |
| `emailHelper.ts` | No connection pool / SMTP verify, errors swallowed silently |
| `config/index.ts` | No env validation — missing secrets silently become `undefined` |
| `QueryBuilder.ts` | Unescaped `searchTerm` allows ReDoS attacks |
| `processReqBody.ts` | Filename collision possible, no sanitization, `console.error` |
| `globalErrorHandler.ts` | Mongoose `validationError` name check uses wrong casing |
| Redis / BullMQ | Installed but never wired — critical for horizontal scaling |
| Passport Google OAuth | `session.endSession()` called twice, Google ID used as password |

---

## Module-by-Module Issues & Fixes

---

### 1. 🔴 Config Validation (`src/config/index.ts`)

**Issues:**
- No runtime validation — a missing `JWT_SECRET` or `DATABASE_URL` causes silent failures that only surface at runtime
- `DATABASE_URL` env var is `database_url` (lowercase) but accessed as `DATABASE_URL` — already broken
- No `cors_origins` config key, so origin whitelists are hardcoded literals
- `BCRYPT_SALT_ROUNDS` missing from `.env` sample

**Fix: Add `zod` schema validation at config load time**

```typescript
// BEFORE (silent undefined)
database_url: process.env.DATABASE_URL,

// AFTER (throws at startup with clear message)
import { z } from 'zod'
const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  BCRYPT_SALT_ROUNDS: z.coerce.number().int().min(10).max(14),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(5000),
  // ... all others
})
const env = envSchema.parse(process.env)
export default env
```

**Also add:**
- `ALLOWED_ORIGINS` comma-separated env var consumed in `app.ts`
- Fix the `database_url` → `DATABASE_URL` casing inconsistency

---

### 2. 🔴 App Bootstrap (`src/app.ts`)

**Issues:**
- `cors({ origin: '*' })` — allows any origin, including malicious ones
- No `helmet` — missing 12+ security HTTP headers (CSP, HSTS, X-Frame-Options etc.)
- No global rate limiter — the entire API is open to brute-force/DDoS
- `express.json()` has no `limit` — allows multi-MB JSON bombs
- `express.static('uploads')` serves files without `Cache-Control` or access control

**Fixes:**

```bash
npm install helmet express-rate-limit
```

```typescript
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'

app.use(helmet())                        // 🔴 add security headers
app.use(express.json({ limit: '50kb' })) // 🔴 body size cap

app.use(cors({
  origin: config.allowed_origins,        // 🔴 explicit allowlist
  credentials: true,
}))

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests.' }
})
app.use('/api', globalLimiter)           // 🔴 global rate limit

// Auth routes get a tighter limiter
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 })
app.use('/api/v1/auth', authLimiter)
```

---

### 3. 🔴 Server Bootstrap (`src/server.ts`)

**Issues:**
- `let server: any` — untyped, should be `http.Server`
- `onlineUsers` Map exported from `server.ts` — this creates a circular dependency risk and a singleton that doesn't survive multi-process deployment
- `await UserServices.createAdmin()` is called in the hot path with no error isolation — if it throws, the server never starts
- Socket.IO `cors: { origin: '*' }` — must match HTTP CORS policy
- `process.on('SIGTERM')` calls `server.close()` but never closes the Mongoose connection
- `mongoose.connect()` is not awaited properly (missing `await` will surface as race condition in some environments)

**Fixes:**

```typescript
import http from 'http'
let server: http.Server

// Await DB connection correctly
await mongoose.connect(config.DATABASE_URL)

// Admin seed with isolation
try { await UserServices.createAdmin() }
catch (e) { errorLogger.error('Admin seed failed (non-fatal)', e) }

// SIGTERM with full graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received — shutting down gracefully')
  server.close(async () => {
    await mongoose.disconnect()
    // await redisClient.quit()  ← add when Redis is wired
    logger.info('Shutdown complete')
    process.exit(0)
  })
})
```

Move `onlineUsers` to Redis (see Socket section).

---

### 4. 🔴 Auth HTTP Middleware (`src/app/middleware/auth.ts`)

**Issues:**
- Returns `404 Not Found` for a missing token — semantically wrong. MUST be `401 Unauthorized`
- `tempAuth` duplicates 95% of the `auth` logic — violates DRY and is a maintenance liability
- Inner `try/catch` re-throws as generic `FORBIDDEN` for ANY error, losing `TokenExpiredError` distinction sometimes
- No check that `tokenWithBearer.startsWith('Bearer ')` uses a space (just checks `'Bearer'` without space — a token starting with `"Bearerxxx"` would slice to wrong position)

**Fixes:**

```typescript
// BEFORE
throw new ApiError(StatusCodes.NOT_FOUND, 'Token not found!')
// AFTER
throw new ApiError(StatusCodes.UNAUTHORIZED, 'Authentication required.')

// BEFORE: duplicate tempAuth function
// AFTER: unified factory
const makeAuth = (secretKey: Secret) => (...roles: string[]) => async (req, res, next) => {
  // ... single implementation using secretKey
}

export const auth = makeAuth(config.jwt.jwt_secret as Secret)
export const tempAuth = makeAuth(config.jwt.temp_jwt_secret as Secret)
```

---

### 5. 🟡 Custom Auth Service (`src/app/modules/auth/custom.auth/custom.auth.service.ts`)

**Issues:**
- **OTP expiry is hardcoded to 2 minutes** in `src/utils/crypto.ts` (`OTP_EXPIRY_MINUTES = 2`) — should be env-configurable
- **Dev OTP leaked in HTTP response body** (`return \`${email}, ${otp}\``) — this must be log-only, never in the response
- `getRefreshToken` performs `User.findById(authId)` but `authId` from the token is the user's `_id`, yet the function name says `authId` — verify the JWT payload field matches exactly
- `socialLogin` — no transaction, user creation and FCM token update happen in separate operations
- `adminLogin` — calls `AuthHelper.isPasswordMatched` directly instead of `User.isPasswordMatched` (inconsistency with the rest of the codebase)
- `resetPassword` — `user.verified = true` is set unconditionally during reset, even for users who were previously unverified for other reasons
- Password validation regex in `auth.validation.ts` requires only 6 chars min — production should enforce 8+ with complexity

**Fixes:**

```typescript
// OTP expiry via env
const OTP_EXPIRY_MINUTES = Number(config.otp_expiry_minutes) || 5

// Never leak OTP in response
return 'An OTP has been sent to your email.'
// Log it only in development: logger.debug(`[DEV] OTP for ${email}: ${otp}`)

// Password min length → 8 chars with complexity rule (already partially done in createUser schema)
password: z.string().min(8).regex(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])/)
```

---

### 6. 🔴 Socket Infrastructure (`src/helpers/socketHelper.ts` + `src/helpers/socketInstances.ts`)

**Issues:**
- **`onlineUsers` is an in-process `Map`** — in a multi-process (PM2 cluster) or multi-server deployment, each process has its own map. User A on Process 1 is invisible to Process 2. This is a **showstopper for horizontal scaling**.
- **Socket.IO `cors: { origin: '*' }`** — must be locked down same as HTTP
- **`socketInstances.ts` uses `console.warn/error`** instead of the structured `logger`
- **`utils/socket.ts` uses `global.io`** — an anti-pattern that breaks TypeScript safety and the module system. This file should be deleted and replaced with the `getSocketIO()` from `socketInstances.ts`
- `registerEventHandlers` is nearly empty — the commented-out notification delivery code should be re-enabled properly
- No room-based architecture — all events are currently broadcast globally

**Fix: Wire in Redis Adapter for horizontal scaling**

```bash
npm install @socket.io/redis-adapter ioredis
# (already in devDependencies — move to dependencies!)
```

```typescript
// server.ts
import { createAdapter } from '@socket.io/redis-adapter'
import { createClient } from 'ioredis'

const pubClient = createClient({ host: config.redis.host, port: config.redis.port })
const subClient = pubClient.duplicate()
await Promise.all([pubClient.connect(), subClient.connect()])
io.adapter(createAdapter(pubClient, subClient))
```

**Fix: Replace `onlineUsers` Map with Redis**

```typescript
// socketHelper.ts
import { redisClient } from '../config/redis'

// On connect
await redisClient.hset('online_users', socket.user.authId, socket.id)

// On disconnect
await redisClient.hdel('online_users', socket.user.authId)

// To check if user is online
const socketId = await redisClient.hget('online_users', userId)
```

**Fix: Delete `src/utils/socket.ts`** and update `notificationHelper.ts` to use `getSocketIO()`.

---

### 7. 🟡 Socket Auth Middleware (`src/app/middleware/socketAuth.ts`)

**Issues:**
- `extractToken` parses `JSON.parse(token)` — this is fragile and dangerous (parse of user-controlled string)
- `handleSocketRequest` is duplicating JWT verification logic already done in `socketAuth` — should reuse
- `handleSocketError` references `error.message` without null-check — can throw if `error` is not an `Error` instance
- `ZodSchema` import is unused if `validateEventData` is the only consumer — fine, but should be documented

**Fixes:**
- Simplify `extractToken` — accept only standard `Bearer <token>` or raw token; reject malformed JSON tokens
- Consolidate `socketAuth` + `handleSocketRequest` into one verified-user getter

---

### 8. 🟡 Notification System (`src/helpers/notificationHelper.ts` + `src/app/modules/notifications/`)

**Issues:**
- `socket.emit('notification', ...)` broadcasts to **ALL connected clients** — a serious privacy/security bug! User A would receive User B's notifications.
- `utils/socket.ts` exports `global.io` — an anti-pattern
- `Notification.create()` is a direct DB write — no error catching for DB failures
- `getNotifications` uses `.populate('to').populate('from')` — unoptrolled population, can return the full user document including sensitive fields
- No unread count included in the listing response payload

**Fixes:**

```typescript
// BEFORE (broadcasts to everyone!)
socket.emit('notification', socketResponse)

// AFTER (targeted room emit)
const io = getSocketIO()
io?.to(`user:${to}`).emit('notification', socketResponse)

// And in socketHelper, join user to their room on connect:
socket.join(`user:${socket.user.authId}`)
```

```typescript
// Populate only safe fields
.populate('from', 'name profile _id')
.populate('to', 'name _id')
```

---

### 9. 🟡 Email Helper (`src/helpers/emailHelper.ts`)

**Issues:**
- Nodemailer transporter is created **once at module load** — no connection pool management, no SMTP `verify()` check on startup
- Errors are caught and logged but **the caller never knows** — `sendEmail` should either return a result or let errors propagate so the caller can handle retries (BullMQ is already installed!)
- No retry logic — a transient SMTP error silently drops the email
- Email `from` field hardcodes `"Express-Craft"` — should use `config.platform_name`

**Fix: Use BullMQ for resilient email delivery**

```typescript
// emailQueue.ts
import { Queue } from 'bullmq'
export const emailQueue = new Queue('email', { connection: redisClient })

// Add to queue instead of sending directly
await emailQueue.add('send', { to, subject, html }, {
  attempts: 3,
  backoff: { type: 'exponential', delay: 5000 },
})

// emailWorker.ts (runs separately or in same process)
import { Worker } from 'bullmq'
new Worker('email', async job => {
  await transporter.sendMail(job.data)
}, { connection: redisClient })
```

---

### 10. 🟡 Push Notification Helper (`src/helpers/pushnotificationHelper.ts`)

**Issues:**
- `admin.initializeApp()` is called at **module import time** — if `FIREBASE_SERVICE_ACCOUNT_BASE64` is missing or malformed, the entire application crashes on startup
- `JSON.parse(serviceAccountJson)` at top level — will throw synchronously before any error handler can catch it
- No check for stale/invalid FCM tokens — `messaging-registration-token-not-registered` errors should trigger an FCM token cleanup
- `sendPushNotification` errors are caught but not re-thrown — the notification silently fails

**Fix: Lazy initialization with error guard**

```typescript
let firebaseApp: admin.app.App | null = null

const getFirebaseApp = (): admin.app.App => {
  if (firebaseApp) return firebaseApp
  const base64 = config.firebase_service_account_base64
  if (!base64) throw new Error('Firebase service account not configured')
  const serviceAccount = JSON.parse(Buffer.from(base64, 'base64').toString('utf8'))
  firebaseApp = admin.initializeApp({ credential: admin.credential.cert(serviceAccount) })
  return firebaseApp
}

// And handle stale tokens
if (error.code === 'messaging/registration-token-not-registered') {
  await User.findOneAndUpdate({ fcmToken }, { $unset: { fcmToken: 1 } })
}
```

---

### 11. 🟡 JWT Helper (`src/helpers/jwtHelper.ts`)

**Issues:**
- `verifyToken` re-throws the raw `JsonWebTokenError` without wrapping — callers must know to catch and check `error.name`
- No `algorithm` option specified in `jwt.sign` — defaults to `HS256` which is fine but should be explicit
- No utility to decode without verification (useful for extracting expiry info)

**Fix:**

```typescript
const createToken = (payload: object, secret: Secret, expireTime: string) => {
  return jwt.sign(payload, secret, {
    expiresIn: expireTime,
    algorithm: 'HS256',  // explicit
  })
}

// Add a decode utility
const decodeToken = (token: string): JwtPayload | null => {
  return jwt.decode(token) as JwtPayload | null
}
```

---

### 12. 🟡 Global Error Handler (`src/app/middleware/globalErrorHandler.ts`)

**Issues:**
- Mongoose `validationError` check uses `error?.name === 'validationError'` (lowercase 'v') — Mongoose actually throws `ValidationError` (uppercase V) — **this branch never runs**
- `handleValidationError` is imported as `handleValidationError` but then also as `handleZodError` — there are duplicate imports of the same file which is a bug
- Default `message` has a typo: `'Something wen wrong!'` → should be `'Something went wrong!'`
- Error stack is sent in response even though the comment suggests otherwise — the condition `config.node_env === 'production' ? undefined : error?.stack` is correct but the stack should also be logged server-side
- No handling for MongoDB duplicate key errors (`error.code === 11000`)

**Fix:**

```typescript
// BEFORE (never fires!)
if (error?.name === 'validationError') {

// AFTER
if (error?.name === 'ValidationError') {  // Mongoose uppercase

// Add duplicate key handler
} else if (error?.code === 11000) {
  statusCode = StatusCodes.CONFLICT
  const field = Object.keys(error.keyPattern || {})[0] || 'field'
  message = `A record with this ${field} already exists.`
  errorMessages = [{ path: field, message }]
}

// Fix typo
let message = 'Something went wrong!'
```

---

### 13. 🟡 File Upload Handler (`src/app/middleware/fileUploadHandler.ts` + `processReqBody.ts`)

**Issues:**
- `fileUploadHandler.ts` calls `.jpeg().png().jpeg()` — triple-chaining with conflicting formats; the last `.jpeg()` will convert PNGs to JPEG, losing transparency
- Filename generation uses `Math.random()` which is not cryptographically secure — use `crypto.randomBytes`
- No sanitization of the original filename — though filename is generated fresh, the `fieldname` key comes from user input and should be validated
- `processReqBody.ts` stores files in-process memory (for cloud upload path) but then builds a local file path — this path is never actually written anywhere in the memory-storage variant (logic bug)
- Both `fileUploadHandler.ts` and `processReqBody.ts` exist and seem to do the same thing — **consolidate into one**
- `console.error('Image optimization failed:', err)` — use structured logger

**Fix:**

```typescript
// Sharp chain (pick one format, don't chain conflicts)
const optimized = await sharp(file.buffer)
  .resize({ width: 1024, withoutEnlargement: true })
  .toFormat(file.mimetype === 'image/png' ? 'png' : 'jpeg', { quality: 80 })
  .toBuffer()

// Secure filename
import { randomBytes } from 'crypto'
const filename = `${Date.now()}-${randomBytes(8).toString('hex')}.${ext}`
```

---

### 14. 🟢 QueryBuilder (`src/app/builder/QueryBuilder.ts`)

**Issues:**
- `searchTerm` is passed directly to `$regex` without escaping — a user can send `.*.*.*.*` causing catastrophic backtracking (ReDoS)
- `sort` is passed directly to Mongoose without validation — a user can inject any field name as a sort key, potentially exposing internal fields or causing performance issues
- No maximum `limit` cap — `?limit=999999` would return the full collection

**Fix:**

```typescript
// Escape regex special chars
const escapeRegex = (str: string) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

search(searchableFields: string[]) {
  if (this?.query?.searchTerm) {
    const safe = escapeRegex(this.query.searchTerm as string)
    this.modelQuery = this.modelQuery.find({
      $or: searchableFields.map(field => ({ [field]: { $regex: safe, $options: 'i' } }))
    })
  }
  return this
}

// Cap limit
paginate() {
  const MAX_LIMIT = 100
  let limit = Math.min(Number(this?.query?.limit) || 10, MAX_LIMIT)
  // ...
}

// Whitelist sort fields (called with allowedSortFields param)
sort(allowedFields: string[]) {
  const rawSort = (this?.query?.sort as string) || '-createdAt'
  const field = rawSort.startsWith('-') ? rawSort.slice(1) : rawSort
  const sort = allowedFields.includes(field) ? rawSort : '-createdAt'
  this.modelQuery = this.modelQuery.sort(sort)
  return this
}
```

---

### 15. 🟢 Verification Service (`src/app/modules/verification/verification.service.ts`)

**Issues:**
- Rate limiting is done in the DB (`Verification.findOne`)  — with no Redis layer, this creates an N+1 DB call on every OTP request
- `validateOtpRequest` uses a fixed 15-minute window message but the env var is `MAX_OTP_REQUEST_ALLOWED` with no time window specified in config
- `upsertVerification` does not use a session — if called within a transaction context, the upsert won't be part of the transaction

**Recommendation:** Move OTP rate limiting metadata to Redis using `INCR` + `EXPIRE` pattern for sub-millisecond rate check without a DB roundtrip.

---

### 16. 🟢 Passport Google Auth (`src/app/modules/auth/passport.auth/passport.auth.service.ts`)

**Issues:**
- `await session.endSession()` is called in both the `try` block and the `finally` block — double call
- Google OAuth `id` is stored as the user's `password` — this is never validated by bcrypt anyway (Google users can't use password login), but it's a confusing security anti-pattern; use a random strong password or a dedicated `provider`/`providerAccountId` field instead

**Fix:**

```typescript
// Replace Google ID as password
password: crypto.randomBytes(32).toString('hex')  // unusable random password
// OR add provider fields to user model
provider: 'google',
providerId: id,
```

---

## New Infrastructure to Add

### Redis Client (`src/config/redis.ts`) 🔴

BullMQ and `@socket.io/redis-adapter` are already in dependencies — they need a shared Redis client:

```typescript
import { Redis } from 'ioredis'
import config from './index'

export const redisClient = new Redis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  maxRetriesPerRequest: null, // required for BullMQ
  lazyConnect: true,
})

redisClient.on('error', (err) => errorLogger.error('Redis error:', err))
```

Required env vars to add:
```
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=
```

---

### HTTP Security Headers (Helmet) 🔴

```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}))
```

---

## Implementation Order (Recommended)

```
Phase 1 — Critical Security & Stability (1–2 days)
  1. Config validation with Zod
  2. Helmet + CORS lockdown
  3. Rate limiters (global + auth routes)
  4. Fix 404→401 in auth.ts
  5. Fix Mongoose validationError name casing in globalErrorHandler
  6. Fix notification privacy bug (targeted room emit)
  7. Fix Firebase lazy initialization

Phase 2 — Scalability Foundation (2–3 days)
  8. Wire Redis client
  9. Wire Socket.IO Redis adapter
  10. Replace onlineUsers Map with Redis hset/hdel
  11. User room join on socket connect
  12. Wire BullMQ email queue + worker

Phase 3 — Code Quality & Hardening (2 days)
  13. ReDoS fix in QueryBuilder
  14. Consolidate fileUploadHandler + processReqBody
  15. Fix Sharp triple-chain image processing
  16. DRY up auth / tempAuth middleware
  17. Stale FCM token cleanup in push notification
  18. Fix Passport Google OAuth session.endSession double call
  19. Remove dev OTP from response body (log-only)
  20. Add MongoDB duplicate key error handling

Phase 4 — Production Ops (1 day)
  21. Graceful shutdown (DB + Redis + Socket close)
  22. Add OTP_EXPIRY_MINUTES to config
  23. Add ALLOWED_ORIGINS to config
  24. Add production build script (tsc + separate process manager config)
```

---

## Files Changed Summary

| File | Change Type | Priority |
|---|---|---|
| `src/config/index.ts` | Modify — add Zod env validation | 🔴 Critical |
| `src/config/redis.ts` | **New** — Redis client singleton | 🔴 Critical |
| `src/app.ts` | Modify — Helmet, CORS env, rate limiter, body limit | 🔴 Critical |
| `src/server.ts` | Modify — graceful shutdown, Redis adapter, typed server | 🔴 Critical |
| `src/app/middleware/auth.ts` | Modify — 401 fix, DRY factory pattern | 🔴 Critical |
| `src/app/middleware/globalErrorHandler.ts` | Modify — `ValidationError` casing, typo, duplicate key | 🟡 High |
| `src/app/middleware/socketAuth.ts` | Modify — simplify extractToken, consolidate handlers | 🟡 High |
| `src/helpers/socketHelper.ts` | Modify — Redis onlineUsers, room joins, restore notifications | 🔴 Critical |
| `src/helpers/socketInstances.ts` | Modify — replace console with logger | 🟡 High |
| `src/helpers/notificationHelper.ts` | Modify — targeted `io.to(room).emit()`, remove global.io | 🔴 Critical |
| `src/helpers/pushnotificationHelper.ts` | Modify — lazy init, stale token cleanup | 🟡 High |
| `src/helpers/emailHelper.ts` | Modify — BullMQ queue, platform_name | 🟡 High |
| `src/helpers/emailQueue.ts` | **New** — BullMQ queue + worker | 🟡 High |
| `src/helpers/jwtHelper.ts` | Modify — explicit algorithm, decode utility | 🟢 Standard |
| `src/app/builder/QueryBuilder.ts` | Modify — ReDoS fix, limit cap, sort validation | 🟡 High |
| `src/app/middleware/fileUploadHandler.ts` | Modify — fix Sharp chain, secure filename, use logger | 🟡 High |
| `src/app/middleware/processReqBody.ts` | Modify — consolidate with fileUploadHandler | 🟡 High |
| `src/utils/socket.ts` | **Delete** — replaced by `getSocketIO()` | 🔴 Critical |
| `src/utils/crypto.ts` | Modify — OTP expiry from config | 🟢 Standard |
| `src/app/modules/auth/custom.auth/custom.auth.service.ts` | Modify — remove OTP from response, fix password storage | 🟡 High |
| `src/app/modules/auth/auth.validation.ts` | Modify — stronger password rules | 🟢 Standard |
| `src/app/modules/auth/passport.auth/passport.auth.service.ts` | Modify — fix double endSession, random password | 🟢 Standard |
| `src/app/modules/notifications/notifications.service.ts` | Modify — select safe fields in populate | 🟡 High |
| `.env.example` | Modify — add REDIS_*, ALLOWED_ORIGINS, OTP_EXPIRY_MINUTES | 🔴 Critical |
