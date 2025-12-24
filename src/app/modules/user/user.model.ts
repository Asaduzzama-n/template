import { Schema, model } from 'mongoose'
import { IUser, UserDocument, UserModel } from './user.interface'
import { USER_ROLES, USER_STATUS } from '../../../enum/user'
import config from '../../../config'
import bcrypt from 'bcrypt'

const userSchema = new Schema<IUser, UserModel>(
  {
    name: {
      type: String,
      trim: true,
    },
    email: {
      type: String,
      trim: true,
      unique: true,
    },
    phone: {
      type: String,
      trim: true,
    },
    status: {
      type: String,
      enum: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED, USER_STATUS.DELETED],
      default: USER_STATUS.ACTIVE,
    },
    verified: {
      type: Boolean,
      default: false,
    },
    profile: {
      type: String,
    },
    password: {
      type: String,
      required: true,
      select: false,
    },
    role: {
      type: String,
      default: USER_ROLES.USER,
    },
    address: {
      type: String,
    },
    location: {
      type: {
        type: String,
        default: 'Point',
        enum: ['Point'],
      },
      coordinates: {
        type: [Number],
        default: [0.0, 0.0],
      },
    },
    authentication: {
      type: {
        isRestricted: {
          type: Boolean,
          default: false,
        },
        restrictionLeftAt: {
          type: Date,
          default: null,
        },
        wrongLoginAttempts: {
          type: Number,
          default: 0,
        },
        passwordChangedAt: {
          type: Date,
          default: null,
        },
      },
      default: {},
      select: false,
    },
    appId: {
      type: String,
      select: false,
    },
    fcmToken: {
      type: String,
      select: false,
    },
  },
  {
    timestamps: true,
  },
)

userSchema.index({ location: '2dsphere' })

userSchema.statics.isPasswordMatched = async function (
  givenPassword: string,
  savedPassword: string,
): Promise<boolean> {
  return await bcrypt.compare(givenPassword, savedPassword)
}

userSchema.pre<UserDocument>('save', async function (next) {
  if (!this.isModified('password')) {
    return next()
  }

  this.password = await bcrypt.hash(
    this.password,
    Number(config.bcrypt_salt_rounds),
  )
  next()
})

export const User = model<IUser, UserModel>('User', userSchema)
