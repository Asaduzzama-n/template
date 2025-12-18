import cors from 'cors'
import express, { Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'

import router from './routes'
import { Morgan } from './shared/morgan'
import cookieParser from 'cookie-parser'
import globalErrorHandler from './app/middleware/globalErrorHandler'
import passport from './app/modules/auth/passport.auth/config/passport'
import { requestLogger, errorRequestLogger } from './app/middleware/requestLogger'
import { apiRateLimiter } from './app/middleware/rateLimiter'
import {
  securityHeaders,
  preventParameterPollution,
  sanitizeInput,
  blockSuspiciousUserAgents,
  validateContentType
} from './app/middleware/security'
import config from './config'

const app = express()

// ===========================================
// Security Middleware (apply first)
// ===========================================

// Security headers (Helmet)
app.use(securityHeaders)

// Block suspicious user agents
app.use(blockSuspiciousUserAgents)

// Validate content type for requests with body
app.use(validateContentType)

// Request logging with correlation IDs
app.use(requestLogger)

// Morgan HTTP logging
app.use(Morgan.successHandler)
app.use(Morgan.errorHandler)

// ===========================================
// CORS Configuration
// ===========================================
const corsOptions = {
  origin: config.node_env === 'production'
    ? (process.env.ALLOWED_ORIGINS?.split(',') || ['https://yourdomain.com'])
    : '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID', 'X-Request-ID'],
  exposedHeaders: ['X-Correlation-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
  maxAge: 86400, // 24 hours
}
app.use(cors(corsOptions))

// ===========================================
// Body Parsing with Size Limits
// ===========================================
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))
app.use(cookieParser())

// Sanitize input to prevent NoSQL injection
app.use(sanitizeInput)

// Prevent parameter pollution
app.use(preventParameterPollution)

// Passport initialization
app.use(passport.initialize())

// Static file serving (consider moving to Nginx in production)
app.use(express.static('uploads'))

// Health check endpoint (no rate limiting)
app.get('/health', (req: Request, res: Response) => {
  res.status(StatusCodes.OK).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  })
})

// Readiness check endpoint
app.get('/ready', (req: Request, res: Response) => {
  res.status(StatusCodes.OK).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
  })
})

// Apply global rate limiting to API routes
app.use('/api', apiRateLimiter)

// API routes
app.use('/api/v1', router)

// Root response
app.get('/', (req: Request, res: Response) => {
  res.send(`
    <div style="
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      background: radial-gradient(circle at top left, #1e003e, #5e00a5);
      color: #fff;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      padding: 2rem;
    ">
      <div>
        <h1 style="font-size: 3rem; margin-bottom: 1rem;">
          🛑 Whoa there, hacker man.
        </h1>
        <p style="font-size: 1.4rem; line-height: 1.6;">
          You really just typed <code style="color:#ffd700;">'/'</code> in your browser and expected magic?<br><br>
          This isn't Hogwarts, and you're not the chosen one. 🧙‍♂️<br><br>
          Honestly, even my 404 page gets more action than this route. 💀
        </p>
        <p style="margin-top: 2rem; font-size: 1rem; opacity: 0.7;">
          Now go back... and try something useful. Or not. I'm just a server.
        </p>
      </div>
    </div>
  `)
})

// Error request logger (before global error handler)
app.use(errorRequestLogger)

// Global error handler
app.use(globalErrorHandler)

// 404 handler
app.use((req, res) => {
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: 'Lost, are we?',
    errorMessages: [
      {
        path: req.originalUrl,
        message: "Congratulations, you've reached a completely useless API endpoint 👏",
      },
      {
        path: '/docs',
        message: "Hint: Maybe try reading the docs next time? 📚",
      },
    ],
    roast: "404 brain cells not found. Try harder. 🧠❌",
    timestamp: new Date().toISOString(),
  })
})

export default app
