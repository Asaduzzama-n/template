import crypto from 'crypto'
import bcrypt from 'bcrypt'
import config from '../config'

// OTP expiry is now configurable via OTP_EXPIRY_MINUTES env var (default: 5 min)
// Previously hardcoded to 2 minutes with no way to change it without code edits.
const getOtpExpiryMinutes = (): number => config.otp_expiry_minutes

const cryptoToken = (): string => {
  return crypto.randomBytes(32).toString('hex')
}

export default cryptoToken

export const hashOtp = async (otp: string): Promise<string> => {
  return bcrypt.hash(otp, Number(config.bcrypt_salt_rounds))
}

export const compareOtp = async (
  otp: string,
  hashedOtp: string,
): Promise<boolean> => {
  return bcrypt.compare(otp, hashedOtp)
}

export const generateOtp = async (): Promise<{
  otp: string
  expiresIn: Date
  hashedOtp: string
}> => {
  const expiryMinutes = getOtpExpiryMinutes()
  const otp = crypto.randomInt(100_000, 999_999).toString()
  const expiresIn = new Date(Date.now() + expiryMinutes * 60 * 1000)
  const hashedOtp = await hashOtp(otp)
  return { otp, expiresIn, hashedOtp }
}
