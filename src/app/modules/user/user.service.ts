import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import { IUser } from './user.interface'
import { User } from './user.model'

import { USER_STATUS } from '../../../enum/user'
import { generateOtp } from '../../../utils/crypto'
import { emailTemplate } from '../../../shared/emailTemplate'
import { emailHelper } from '../../../helpers/emailHelper'
import { JwtPayload } from 'jsonwebtoken'

const createUser = async (payload: IUser): Promise<IUser | null> => {
  //check if user already exist
  payload.email = payload.email?.toLowerCase().trim()
  const isUserExist = await User.findOne({
    email: payload.email,
    status: { $nin: [USER_STATUS.DELETED] },
  })

  if (isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `An account with this email already exist, please login or try with another email.`,
    )
  }

  const user = await User.create([payload])
  if (!user) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user')
  }

  const otp = generateOtp()
  const otpExpiresIn = new Date(Date.now() + 5 * 60 * 1000)
  const authentication = {
    oneTimeCode: otp,
    expiresAt: otpExpiresIn,
    latestRequestAt: new Date(),
    authType: 'createAccount',
  }

  await User.findByIdAndUpdate(
    user[0]._id,
    {
      $set: { authentication },
    },
    { new: true },
  )

  //send email or sms with otp
  const createAccount = emailTemplate.createAccount({
    name: user[0].name!,
    email: user[0].email!,
    otp,
  })

  emailHelper.sendEmail(createAccount)

  return user[0]
}

const updateProfile = async (user: JwtPayload, payload: Partial<IUser>) => {
  // console.log(first)
  const updatedProfile = await User.findOneAndUpdate(
    { _id: user.authId, status: { $nin: [USER_STATUS.DELETED] } },
    {
      $set: payload,
    },
    { new: true },
  )

  if (!updatedProfile) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to update profile.')
  }

  return 'Profile updated successfully.'
}

export const UserServices = { createUser, updateProfile }
