/* eslint-disable no-undef */
import dotenv from 'dotenv'
import path from 'path'
dotenv.config({ path: path.join(process.cwd(), '.env') })

export default {
  // ============================================
  // App Configuration
  // ============================================
  app: {
    node_env: process.env.NODE_ENV,
    port: process.env.PORT,
    ip_address: process.env.IP_ADDRESS,
    platform_name: process.env.PLATFORM_NAME,
  },

  // ============================================
  // Database Configuration
  // ============================================
  database: {
    url: process.env.DATABASE_URL,
  },

  // ============================================
  // Security Configuration
  // ============================================
  security: {
    bcrypt_salt_rounds: process.env.BCRYPT_SALT_ROUNDS,
    lock_out_strategy: process.env.LOCKOUT_STRATEGY,
    max_wrong_attempts: process.env.MAX_WRONG_ATTEMPTS,
    restriction_minutes: process.env.RESTRICTION_MINUTES,
  },

  // ============================================
  // JWT Configuration
  // ============================================
  jwt: {
    jwt_secret: process.env.JWT_SECRET,
    jwt_expire_in: process.env.JWT_EXPIRE_IN,
    jwt_refresh_secret: process.env.JWT_REFRESH_SECRET,
    jwt_refresh_expire_in: process.env.JWT_REFRESH_EXPIRES_IN,
    temp_jwt_secret: process.env.TEMP_JWT_SECRET,
    temp_jwt_expire_in: process.env.TEMP_JWT_EXPIRE_IN,
  },

  // ============================================
  // OTP Configuration
  // ============================================
  otp: {
    request_cooldown_seconds: process.env.OTP_REQUEST_COOLDOWN_SECONDS,
    max_attempts: process.env.MAX_OTP_ATTEMPTS,
    max_request_allowed: process.env.MAX_OTP_REQUEST_ALLOWED,
  },

  // ============================================
  // Admin Configuration
  // ============================================
  admin: {
    email: process.env.ADMIN_EMAIL,
    password: process.env.ADMIN_PASSWORD,
  },

  // ============================================
  // Email Configuration
  // ============================================
  email: {
    from: process.env.EMAIL_FROM,
    user: process.env.EMAIL_USER,
    port: process.env.EMAIL_PORT,
    host: process.env.EMAIL_HOST,
    pass: process.env.EMAIL_PASS,
  },

  // ============================================
  // AWS Configuration
  // ============================================
  aws: {
    access_key_id: process.env.AWS_ACCESS_KEY_ID,
    secret_access_key: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
    bucket_name: process.env.AWS_BUCKET_NAME,
  },

  // ============================================
  // Google OAuth Configuration
  // ============================================
  google: {
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    callback_url: process.env.GOOGLE_CALLBACK_URL,
  },

  // ============================================
  // Firebase Configuration
  // ============================================
  firebase: {
    service_account_base64: process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
  },

  // ============================================
  // Stripe Configuration
  // ============================================
  stripe: {
    secret_key: process.env.STRIPE_SECRET_KEY,
    account_id: process.env.STRIPE_ACCOUNT_ID,
    webhook_secret: process.env.WEBHOOK_SECRET,
    application_fee: process.env.APPLICATION_FEE,
    instant_transfer_fee: process.env.INSTANT_TRANSFER_FEE,
  },

  // ============================================
  // Twilio Configuration
  // ============================================
  twilio: {
    account_sid: process.env.TWILIO_ACCOUNT_SID,
    auth_token: process.env.TWILIO_AUTH_TOKEN,
    phone_number: process.env.TWILIO_PHONE_NUMBER,
  },

  // ============================================
  // Cloudinary Configuration
  // ============================================
  cloudinary: {
    name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    secret: process.env.CLOUDINARY_SECRET,
  },

  // ============================================
  // OpenAI Configuration
  // ============================================
  openai: {
    api_key: process.env.OPENAI_API_KEY,
  },
}
