import { Schema, model } from 'mongoose'
import { IOtp, OtpModel } from './otp.interface'

const otpSchema = new Schema<IOtp, OtpModel>(
  {
    email: {
      type: String,
    },
    phone: {
      type: String,
    },
    restrictionLeftAt: { type: Date },
    resetPassword: { type: Boolean, default: false },
    wrongLoginAttempts: { type: Number, default: 0 },
    passwordChangedAt: { type: Date },
    oneTimeCode: { type: String },
    latestRequestAt: { type: Date, default: null },
    expiresAt: { type: Date, default: null },
    requestCount: { type: Number, default: 0 },
    authType: { type: String },
    createdAt: { type: Date },
    updatedAt: { type: Date },
  },
  {
    timestamps: true,
  },
)

export const Otp = model<IOtp, OtpModel>('Otp', otpSchema)
