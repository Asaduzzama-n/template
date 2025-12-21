import crypto from 'crypto'
import bcrypt from 'bcrypt'
import config from '../config'

const OTP_EXPIRY_MINUTES = 2

const cryptoToken = () => {
  return crypto.randomBytes(32).toString('hex')
}

export default cryptoToken

export const hashOtp = async (otp: string): Promise<string> => {
  const hashedOtp = await bcrypt.hash(otp, Number(config.bcrypt_salt_rounds))
  return hashedOtp
}
export const compareOtp = async (otp: string, hashedOtp: string): Promise<boolean> => {
  const isMatch = await bcrypt.compare(otp, hashedOtp)
  return isMatch
}
export const generateOtp = async () => {
  const otp = crypto.randomInt(100000, 999999).toString()
  const expiresIn = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000)
  const hashedOtp = await hashOtp(otp)
  return {otp, expiresIn, hashedOtp}
}
