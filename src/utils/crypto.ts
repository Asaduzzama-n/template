import crypto from 'crypto'
import bcrypt from 'bcrypt'

const cryptoToken = () => {
  return crypto.randomBytes(32).toString('hex')
}

export default cryptoToken

export const hashOtp = async (otp: string): Promise<string> => {
  return await bcrypt.hash(otp, 10)
}
export const compareOtp = async (otp: string, hashedOtp: string): Promise<boolean> => {
  return await bcrypt.compare(otp, hashedOtp)
}
export const generateOtp = async () => {
  const otp = crypto.randomInt(100000, 999999).toString()
  //return both otp and hashed otp
  return {
    otp,
    hashedOtp: await hashOtp(otp),
  }
}
