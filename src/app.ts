import cors from 'cors'
import express, { Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import router from './routes'
import { Morgan } from './shared/morgan'
import cookieParser from 'cookie-parser'
import globalErrorHandler from './app/middleware/globalErrorHandler'
import passport from './app/modules/auth/passport.auth/config/passport'

const app = express()

// Security Headers
app.use(helmet())

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes',
  },
})

// Apply rate limiter to all routes
app.use(limiter)

// Proxy trust (important for rate limiting if behind a proxy like Nginx/Heroku)
app.set('trust proxy', 1)

// Morgan logging
app.use(Morgan.successHandler)
app.use(Morgan.errorHandler)

// CORS
app.use(
  cors({
    origin: '*', // In production, replace with specific allowed origins
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }),
)

// Body parser
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))
app.use(cookieParser())

// Passport
app.use(passport.initialize())

// Static files
app.use(express.static('uploads'))

// Router
app.use('/api/v1', router)

// Live response (Root)
app.get('/', (req: Request, res: Response) => {
  res.status(StatusCodes.OK).json({
    success: true,
    message: 'Welcome to the API Service',
    version: '1.0.0',
    status: 'Operational',
  })
})

// Global error handler
app.use(globalErrorHandler)

// 404 Not Found route
app.use((req: Request, res: Response) => {
  res.status(StatusCodes.NOT_FOUND).json({
    success: false,
    message: 'The requested resource was not found on this server',
    errorMessages: [
      {
        path: req.originalUrl,
        message: 'API endpoint does not exist',
      },
    ],
    timestamp: new Date().toISOString(),
  })
})

export default app

