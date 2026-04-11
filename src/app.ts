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
      background: linear-gradient(135deg, #fff5e6 0%, #ffebcc 100%);
      color: #333;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      overflow: hidden;
      position: relative;
    ">
      <!-- Decorative Spiral Style (Hidden Leaf Vibe) -->
      <div style="
        position: absolute;
        top: -100px;
        right: -100px;
        width: 400px;
        height: 400px;
        background: radial-gradient(circle, rgba(255, 144, 0, 0.15) 0%, transparent 70%);
        border-radius: 50%;
      "></div>

      <div style="
        background: rgba(255, 255, 255, 0.6);
        backdrop-filter: blur(15px);
        padding: 4rem;
        border-radius: 24px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.08);
        max-width: 600px;
        border-top: 6px solid #ff9000;
        z-index: 10;
      ">
        <div style="font-size: 5rem; margin-bottom: 1.5rem;">🌀</div>
        <h1 style="font-size: 2.5rem; margin-bottom: 1rem; color: #e67e00; text-transform: uppercase; letter-spacing: 2px; font-weight: 800;">
          Dattebayo! 🍥
        </h1>
        <p style="font-size: 1.2rem; line-height: 1.6; color: #555;">
          You've reached the gateway of the <br>
          <span style="color: #ff9000; font-weight: 700;">Hidden Leaf Backend</span>. <br><br>
          There's no jutsu at the root <code style="background: #fff; border: 1px solid #fee2b3; padding: 2px 8px; border-radius: 6px; color: #d97706; font-weight: 600;">'/'</code>, ninja. <br>
          If you're looking for the API, it's hidden under <code style="color: #e67e00; font-weight: 600;">/api/v1</code>. ⚔️
        </p>
        <p style="margin-top: 2.5rem; font-size: 1rem; font-style: italic; color: #888; border-top: 1px solid #eee; pt: 1.5rem;">
          "I'm not gonna run away, I never go back on my word! That's my nindo: my ninja way!"
        </p>
      </div>
      
      <!-- Bottom Decorative Element -->
      <div style="
        position: absolute;
        bottom: 2rem;
        width: 100%;
        font-size: 0.85rem;
        color: #bfa58a;
        font-weight: 600;
        letter-spacing: 2px;
        text-transform: uppercase;
      ">
        ESTABLISHED BY THE FIRST HOKAGE OF CODE
      </div>
    </div>
  `)
})

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use(globalErrorHandler)

// ─── 404 Handler (Hybrid Ninja Guard) ────────────────────────────────────────
app.use((req: Request, res: Response) => {

  if (req.accepts('html')) {
    res.status(StatusCodes.NOT_FOUND).send(`
      <div style="
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background: linear-gradient(135deg, #fff5e6 0%, #ffebcc 100%);
        color: #333;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        text-align: center;
        overflow: hidden;
        position: relative;
      ">
        <div style="
          background: rgba(255, 255, 255, 0.6);
          backdrop-filter: blur(15px);
          padding: 4rem;
          border-radius: 24px;
          box-shadow: 0 10px 40px rgba(0,0,0,0.08);
          max-width: 600px;
          border-top: 6px solid #ff4444; /* Red for Error/Warning */
          z-index: 10;
        ">
          <div style="font-size: 5rem; margin-bottom: 1.5rem;">🐾</div>
          <h1 style="font-size: 2.5rem; margin-bottom: 1rem; color: #ff4444; text-transform: uppercase; letter-spacing: 2px; font-weight: 800;">
            404 NOT FOUND
          </h1>
          <p style="font-size: 1.2rem; line-height: 1.6; color: #555;">
            Whoops! It looks like you've wandered into the <br>
            <span style="color: #ff4444; font-weight: 700;">Forest of Death</span>. <br><br>
            The jutsu at <code style="background: #fff; border: 1px solid #ffcccc; padding: 2px 8px; border-radius: 6px; color: #ff4444; font-weight: 600;">${req.originalUrl}</code> doesn't exist! <br>
            Did your Shadow Clone get lost on the way? 💨
          </p>
          <a href="/" style="
            display: inline-block;
            margin-top: 2rem;
            padding: 0.8rem 2rem;
            background: #ff9000;
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: bold;
            box-shadow: 0 4px 15px rgba(255, 144, 0, 0.3);
          ">RETURN TO THE VILLAGE</a>
        </div>
      </div>
    `)
    return;
  }

  // 2. Default to JSON for API/Tooling requests
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: 'Lost in the Forest of Death, skip? 🐾',
    errorMessages: [
      {
        path: req.originalUrl,
        message:
          "Your Shadow Clone couldn't find this jutsu (route). It just poofed! 💨",
      },
      {
        path: '/api/v1',
        message: "Hint: Try the main Chunin Exam gate at '/api/v1'! ⛩️",
      },
    ],
    timestamp: new Date().toISOString(),
  })
})

export default app
