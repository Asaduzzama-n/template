export enum RedisKeys {
  TERMS_AND_CONDITION = 'terms-and-condition',
  PRIVACY_POLICY = 'privacy-policy',
  FAQ = 'faq',
}

/**
 * Rate limiting key prefixes for auth operations.
 * Used with redisHelper to build full keys.
 */
export enum AuthRateLimitKeys {
  OTP_RESEND = 'otp-resend',
  PASSWORD_RESET = 'password-reset',
  LOGIN_ATTEMPT = 'login-attempt',
}