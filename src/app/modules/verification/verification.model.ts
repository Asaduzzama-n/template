import { Schema, model } from 'mongoose'
import {
  IVerification,
  VerificationModel,
  TypeEnum,
} from './verification.interface'

const verificationSchema = new Schema<IVerification, VerificationModel>(
  {
    type: { type: String, enum: Object.values(TypeEnum) },
    identifier: { type: String, unique: true, required: true },
    otpHash: { type: String },
    latestRequest: { type: Date },
    expiresAt: { type: Date },
    attempts: { type: Number },
  },
  {
    timestamps: true,
  },
)

verificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

export const Verification = model<IVerification, VerificationModel>(
  'Verification',
  verificationSchema,
)
