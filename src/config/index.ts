/* eslint-disable no-undef */
import dotenv from 'dotenv'
import path from 'path'
import { z } from 'zod'

dotenv.config({ path: path.join(process.cwd(), '.env') })

// ─── Env Schema Validation ───────────────────────────────────────────────────
const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  IP_ADDRESS: z.string().default('127.0.0.1'),
  PORT: z.coerce.number().int().positive().default(5000),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),

  BCRYPT_SALT_ROUNDS: z.coerce.number().int().min(10).max(14).default(12),
  PLATFORM_NAME: z.string().default('Express-Craft'),

  // Admin
  ADMIN_EMAIL: z.string().email().optional(),
  ADMIN_PASSWORD: z.string().min(8).optional(),

  // JWT
  JWT_SECRET: z.string().min(16, 'JWT_SECRET must be at least 16 chars'),
  JWT_EXPIRE_IN: z.string().default('10d'),
  JWT_REFRESH_SECRET: z.string().min(16, 'JWT_REFRESH_SECRET must be at least 16 chars'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('180d'),
  TEMP_JWT_SECRET: z.string().min(16).optional(),
  TEMP_JWT_EXPIRE_IN: z.string().default('15m'),

  // CORS
  ALLOWED_ORIGINS: z.string().default('http://localhost:3000'),

  // Redis
  REDIS_HOST: z.string().default('127.0.0.1'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),

  // Email
  EMAIL_FROM: z.string().optional(),
  EMAIL_USER: z.string().optional(),
  EMAIL_PASS: z.string().optional(),
  EMAIL_PORT: z.coerce.number().int().positive().default(587),
  EMAIL_HOST: z.string().optional(),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_CALLBACK_URL: z.string().url().optional(),

  // AWS S3
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_REGION: z.string().optional(),
  AWS_BUCKET_NAME: z.string().optional(),

  // RustFS (S3 Compatible)
  RUSTFS_ENDPOINT: z.string().optional(),
  RUSTFS_ACCESS_KEY: z.string().optional(),
  RUSTFS_SECRET_KEY: z.string().optional(),
  RUSTFS_REGION: z.string().default('us-east-1'),
  RUSTFS_BUCKET: z.string().optional(),

  // Firebase
  FIREBASE_SERVICE_ACCOUNT_BASE64: z.string().optional(),

  // Twilio
  TWILIO_ACCOUNT_SID: z.string().optional(),
  TWILIO_AUTH_TOKEN: z.string().optional(),
  TWILIO_PHONE_NUMBER: z.string().optional(),

  // Cloudinary
  CLOUDINARY_NAME: z.string().optional(),
  CLOUDINARY_API_KEY: z.string().optional(),
  CLOUDINARY_SECRET: z.string().optional(),

  // Stripe
  STRIPE_SECRET_KEY: z.string().optional(),
  STRIPE_ACCOUNT_ID: z.string().optional(),
  WEBHOOK_SECRET: z.string().optional(),

  // OpenAI
  OPENAI_API_KEY: z.string().optional(),

  // Auth lockout strategy
  LOCKOUT_STRATEGY: z.enum(['STRICT_EARLIEST', 'EXTEND']).default('EXTEND'),
  MAX_WRONG_ATTEMPTS: z.coerce.number().int().positive().default(5),
  RESTRICTION_MINUTES: z.coerce.number().int().positive().default(30),
  OTP_REQUEST_COOLDOWN_SECONDS: z.coerce.number().int().positive().default(60),
  MAX_OTP_ATTEMPTS: z.coerce.number().int().positive().default(5),
  MAX_OTP_REQUEST_ALLOWED: z.coerce.number().int().positive().default(5),
  OTP_EXPIRY_MINUTES: z.coerce.number().int().positive().default(5),

  // App fees
  APPLICATION_FEE: z.string().optional(),
  INSTANT_TRANSFER_FEE: z.string().optional(),
})

// Parse and validate - throws on startup if critical vars missing
const parsed = envSchema.safeParse(process.env)

if (!parsed.success) {
  console.error('❌ Invalid environment variables:\n')
  const issues = parsed.error.issues
  issues.forEach(issue => {
    console.error(`  ${issue.path.join('.')}: ${issue.message}`)
  })
  console.error('\nFix the above variables in your .env file and restart.\n')
  process.exit(1)
}

const env = parsed.data

export default {
  node_env: env.NODE_ENV,
  ip_address: env.IP_ADDRESS,
  port: env.PORT,
  database_url: env.DATABASE_URL,
  bcrypt_salt_rounds: env.BCRYPT_SALT_ROUNDS,
  platform_name: env.PLATFORM_NAME,
  allowed_origins: env.ALLOWED_ORIGINS.split(',').map(o => o.trim()),

  admin: {
    email: env.ADMIN_EMAIL,
    password: env.ADMIN_PASSWORD,
  },

  jwt: {
    jwt_secret: env.JWT_SECRET,
    jwt_expire_in: env.JWT_EXPIRE_IN,
    jwt_refresh_secret: env.JWT_REFRESH_SECRET,
    jwt_refresh_expire_in: env.JWT_REFRESH_EXPIRES_IN,
    temp_jwt_secret: env.TEMP_JWT_SECRET,
    temp_jwt_expire_in: env.TEMP_JWT_EXPIRE_IN,
  },

  redis: {
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
  },

  google: {
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    callback_url: env.GOOGLE_CALLBACK_URL,
  },

  aws: {
    access_key_id: env.AWS_ACCESS_KEY_ID,
    secret_access_key: env.AWS_SECRET_ACCESS_KEY,
    region: env.AWS_REGION,
    bucket_name: env.AWS_BUCKET_NAME,
  },

  rustfs: {
    endpoint: env.RUSTFS_ENDPOINT,
    access_key: env.RUSTFS_ACCESS_KEY,
    secret_key: env.RUSTFS_SECRET_KEY,
    region: env.RUSTFS_REGION,
    bucket: env.RUSTFS_BUCKET,
  },

  firebase_service_account_base64: env.FIREBASE_SERVICE_ACCOUNT_BASE64,

  email: {
    from: env.EMAIL_FROM,
    user: env.EMAIL_USER,
    port: env.EMAIL_PORT,
    host: env.EMAIL_HOST,
    pass: env.EMAIL_PASS,
  },

  twilio: {
    account_sid: env.TWILIO_ACCOUNT_SID,
    auth_token: env.TWILIO_AUTH_TOKEN,
    phone_number: env.TWILIO_PHONE_NUMBER,
  },

  cloudinary: {
    cloudinary_name: env.CLOUDINARY_NAME,
    cloudinary_api_key: env.CLOUDINARY_API_KEY,
    cloudinary_secret: env.CLOUDINARY_SECRET,
  },

  stripe_secret: env.STRIPE_SECRET_KEY,
  stripe_account_id: env.STRIPE_ACCOUNT_ID,
  webhook_secret: env.WEBHOOK_SECRET,
  openAi_api_key: env.OPENAI_API_KEY,

  application_fee: env.APPLICATION_FEE,
  instant_transfer_fee: env.INSTANT_TRANSFER_FEE,

  lock_out_strategy: env.LOCKOUT_STRATEGY,
  max_wrong_attempts: env.MAX_WRONG_ATTEMPTS,
  restriction_minutes: env.RESTRICTION_MINUTES,
  otp_request_cooldown_seconds: env.OTP_REQUEST_COOLDOWN_SECONDS,
  max_otp_attempts: env.MAX_OTP_ATTEMPTS,
  max_otp_request_allowed: env.MAX_OTP_REQUEST_ALLOWED,
  otp_expiry_minutes: env.OTP_EXPIRY_MINUTES,
}
