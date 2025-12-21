import { Schema, model } from 'mongoose'
import { IToken, TokenModel } from './token.interface'

const tokenSchema = new Schema<IToken, TokenModel>(
  {
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    token: {
      type: String,
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      default: new Date(Date.now() + 15 * 60 * 100),
    },
  },
  {
    timestamps: true,
  },
)

tokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })


export const Token = model<IToken, TokenModel>('Token', tokenSchema)
