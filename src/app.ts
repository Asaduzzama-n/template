import cors from 'cors'
import express, { Request, Response } from 'express'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { StatusCodes } from 'http-status-codes'

import router from './routes'
import { Morgan } from './shared/morgan'
import cookieParser from 'cookie-parser'
import globalErrorHandler from './app/middleware/globalErrorHandler'
import passport from './app/modules/auth/strategies/google.strategy'
import config from './config'

const app = express()

// ─── Security Headers ─────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
      },
    },
    hsts: {
      maxAge: 31_536_000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }),
)

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, Postman)
      if (!origin) return callback(null, true)
      if (config.allowed_origins.includes(origin) || config.node_env === 'development') {
        return callback(null, true)
      }
      callback(new Error(`CORS: origin '${origin}' is not allowed`))
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
)

// ─── Body Parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '50kb' }))
app.use(express.urlencoded({ extended: true, limit: '50kb' }))
app.use(cookieParser())

// ─── Request Logging ─────────────────────────────────────────────────────────
app.use(Morgan.successHandler)
app.use(Morgan.errorHandler)

// ─── Passport ────────────────────────────────────────────────────────────────
app.use(passport.initialize())

// ─── Static Files ────────────────────────────────────────────────────────────
app.use('/uploads', express.static('uploads'))

// ─── Global Rate Limiter ──────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes.',
  },
})

// ─── Auth Route Rate Limiter (tighter) ───────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again after 15 minutes.',
  },
})

app.use('/api', globalLimiter)
app.use('/api/v1/auth', authLimiter)

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/v1', router)

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/', (_req: Request, res: Response) => {
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

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use(globalErrorHandler)

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req: Request, res: Response) => {
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
        message: 'Hint: Maybe try reading the docs next time? 📚',
      },
    ],
    timestamp: new Date().toISOString(),
  })
})

export default app
