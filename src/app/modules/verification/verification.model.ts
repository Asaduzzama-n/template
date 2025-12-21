import { Schema, model } from 'mongoose'
import {
  IVerification,
  VerificationModel,
  VERIFICATION_TYPE,
} from './verification.interface'

const verificationSchema = new Schema<IVerification, VerificationModel>(
  {
    type: { type: String, enum: Object.values(VERIFICATION_TYPE) },
    identifier: { type: String, required: true },
    otpHash: { type: String },
    latestRequest: { type: Date, default: null },
    otpExpiresAt: { type: Date, default: null },
    requestCount:{type:Number, default:0},
    expiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 15 * 60 * 1000),
    },
    attempts: { type: Number, default: 0 },
  },
  {
    timestamps: true,
  },
)
verificationSchema.index({ identifier: 1, type: 1 }, { unique: true });
verificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

export const Verification = model<IVerification, VerificationModel>(
  'Verification',
  verificationSchema,
)
