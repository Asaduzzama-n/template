import { StatusCodes } from 'http-status-codes'
import { User } from '../../user/user.model'
import { AuthHelper } from '../auth.helper'
import ApiError from '../../../../errors/ApiError'
import { USER_ROLES, USER_STATUS } from '../../../../enum/user'
import config from '../../../../config'
import { Token } from '../../token/token.model'
import { IAuthResponse, IResetPassword } from '../auth.interface'
import { emailTemplate } from '../../../../shared/emailTemplate'
import cryptoToken, { compareOtp, generateOtp } from '../../../../utils/crypto'
import { IChangePassword, ILoginData } from '../../../../interfaces/auth'
import { AuthCommonServices, authResponse, getSanitizeEmail } from '../common'
import { jwtHelper } from '../../../../helpers/jwtHelper'
import { JwtPayload } from 'jsonwebtoken'
import { IUser } from '../../user/user.interface'
import { emailHelper } from '../../../../helpers/emailHelper'
import {
  IVerification,
  VERIFICATION_TYPE,
} from '../../verification/verification.interface'
import mongoose from 'mongoose'
import { Verification } from '../../verification/verification.model'

//done
const createUser = async (payload: IUser) => {
  const session = await mongoose.startSession()

  try {
    session.startTransaction()

    payload.email = getSanitizeEmail(payload.email)

    const { otp, expiresIn, hashedOtp } = await generateOtp()

    const authentication: Omit<IVerification, 'expiresAt' | 'requestCount'> = {
      identifier: payload.email,
      otpHash: hashedOtp,
      otpExpiresAt: expiresIn,
      latestRequest: new Date(),
      attempts: 1,
      type: VERIFICATION_TYPE.ACCOUNT_ACTIVATION,
    }

    const createAccount = emailTemplate.createAccount({
      name: payload.name!,
      email: payload.email!,
      otp,
    })

    await User.create([payload], { session }),
      await Verification.create([authentication], { session }),
      await session.commitTransaction()

    emailHelper.sendEmail(createAccount)

    return `${config.node_env === 'development' ? `${payload.email}, ${otp}` : 'An otp has been sent to your email, please check.'}`
  } catch (error: any) {
    await session.abortTransaction()
    if (error.code === 11000) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        'An account with this email already exists. Please try with another email or login using this email.',
      )
    }
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'Something went wrong while creating account. Please try again.',
    )
  } finally {
    await session.endSession()
  }
}
//done
const customLogin = async (payload: ILoginData): Promise<IAuthResponse> => {
  const email = getSanitizeEmail(payload.email)

  const user = await User.findOne({
    email,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })
    .select('+password +authentication')
    .lean()

  if (!user) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You provided the wrong credentials, please try again with valid one.',
    )
  }

  if (user.status === USER_STATUS.RESTRICTED) {
    throw new ApiError(
      StatusCodes.FORBIDDEN,
      'Your account has been restricted by an administrator. Please contact support.',
    )
  }

  return await AuthCommonServices.handleLoginLogic(payload, user)
}

const adminLogin = async (payload: ILoginData): Promise<IAuthResponse> => {
  const { email } = payload

  const sanitizedEmail = getSanitizeEmail(email)

  const isUserExist = await User.findOne({
    email: sanitizedEmail,
    status: { $in: [USER_STATUS.ACTIVE] },
  })
    .select('+password +authentication')
    .lean()

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      `Invalid credentials, please try again with valid one.`,
    )
  }

  if (isUserExist.role !== USER_ROLES.ADMIN) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'You are not authorized to login as admin',
    )
  }

  const isPasswordMatch = await AuthHelper.isPasswordMatched(
    payload.password,
    isUserExist.password as string,
  )
  if (!isPasswordMatch) {
    throw new ApiError(
      StatusCodes.UNAUTHORIZED,
      'Please try again with correct credentials.',
    )
  }

  //tokens
  const tokens = AuthHelper.createToken(
    isUserExist._id,
    isUserExist.role,
    isUserExist.name!,
    isUserExist.email!,
  )

  return authResponse(StatusCodes.OK, `Welcome back ${isUserExist.name}`, {
    role: isUserExist.role,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
  })
}

//done
const forgetPassword = async (email: string) => {
  const sanitizedEmail = getSanitizeEmail(email)

  const isUserExist = await User.findOne({
    email: sanitizedEmail,
    status: { $ne: USER_STATUS.DELETED },
  })
    .select('+authentication')
    .lean()

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.NOT_FOUND,
      'No account found with this email.',
    )
  }

  if (isUserExist.status === USER_STATUS.RESTRICTED) {
    throw new ApiError(
      StatusCodes.FORBIDDEN,
      'Your account has been restricted by an administrator. Please contact support.',
    )
  }

  // 2. Check for Account-Level Restrictions (Admin ban or Login Lockout)
  const { isRestricted, restrictionLeftAt } = isUserExist.authentication || {}

  if (isRestricted && restrictionLeftAt && new Date() < restrictionLeftAt) {
    const remaining = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Your account is locked. Try again in ${remaining} minutes.`,
    )
  }

  // 3. Cooldown & Brute Force Check (Verification Model)
  const existingVerification = await Verification.findOne({
    identifier: isUserExist.email,
    type: VERIFICATION_TYPE.RESET_PASSWORD,
  }).lean()

  if (existingVerification) {
    const timeSinceLastRequest =
      (Date.now() - existingVerification.latestRequest.getTime()) / 1000
    const waitTime = Math.ceil(
      Number(config.otp_request_cooldown_seconds) - timeSinceLastRequest,
    )
    if (existingVerification.latestRequest) {
      const secondsSinceLast =
        (Date.now() - existingVerification.latestRequest.getTime()) / 1000
      if (secondsSinceLast < Number(config.otp_request_cooldown_seconds)) {
        throw new ApiError(
          StatusCodes.TOO_MANY_REQUESTS,
          `Please wait ${waitTime} seconds before requesting a new OTP.`,
        )
      }
    }

    // Check Request Limit - NEW
    if (
      existingVerification.requestCount >=
      Number(config.max_otp_request_allowed || 5)
    ) {
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        'Maximum reset attempts reached. Try again in 15 minutes.',
      )
    }
  }

  // 4. Generate OTP
  const { otp, expiresIn, hashedOtp } = await generateOtp()

  // 5. Atomic Upsert to Verification Model (Correct Approach)
  // This manages the cooldown and the OTP data in one place
  await Verification.findOneAndUpdate(
    { identifier: isUserExist.email, type: VERIFICATION_TYPE.RESET_PASSWORD },
    {
      $set: {
        otpHash: hashedOtp,
        otpExpiresAt: expiresIn,
        latestRequest: new Date(),
        // We set the TTL index 'expiresAt' to 15 mins from NOW
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
      $inc: { attempts: 0 }, // Reset attempts for a new OTP
    },
    { upsert: true, new: true },
  )

  // 6. Send Email (Fire and forget or use a Job Queue)
  const forgetPasswordEmailTemplate = emailTemplate.resetPassword({
    name: isUserExist.name as string,
    email: isUserExist.email as string,
    otp,
  })

  emailHelper.sendEmail(forgetPasswordEmailTemplate).catch(err => {
    console.error('Failed to send reset email:', err)
  })

  return config.node_env === 'development'
    ? `An otp-${otp} is being sent to ${email}`
    : 'An OTP has been sent to your email. Please check your inbox.'
}

const resetPassword = async (
  resetToken: string,
  payload: IResetPassword,
): Promise<{ message: string }> => {
  const { newPassword, confirmPassword } = payload
  const session = await mongoose.startSession()

  try {
    session.startTransaction()
    console.log(payload, resetToken)
    // 2. Fetch and Validate Reset Token
    const isTokenExist = await Token.findOne({ token: resetToken }).session(
      session,
    )

    if (!isTokenExist) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        'Invalid or expired reset session. Please verify your account again.',
      )
    }

    // 3. Expiry Check
    if (new Date() > isTokenExist.expiresAt) {
      await Token.deleteOne({ _id: isTokenExist._id }).session(session)
      await session.commitTransaction() // Persist the deletion of expired token
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Reset token has expired.')
    }

    // 4. Fetch User (Include authentication for security reset)
    const user = await User.findById(isTokenExist.user)
      .select('+password +authentication')
      .session(session)

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, 'User account not found.')
    }

    // 5. Admin Status Check (Safety first)
    if (user.status === USER_STATUS.RESTRICTED) {
      throw new ApiError(StatusCodes.FORBIDDEN, 'Your account is restricted.')
    }
    console.log(user)
    user.verified = true
    user.password = newPassword
    user.authentication.passwordChangedAt = new Date()
    user.authentication.wrongLoginAttempts = 0
    user.authentication.isRestricted = false
    user.authentication.restrictionLeftAt = null

    await user.save({ session })

    // 7. CONSUME TOKEN: Delete immediately so it can't be used again (Replay attack protection)
    await Token.deleteOne({ _id: isTokenExist._id }).session(session)

    await session.commitTransaction()

    return {
      message: `Password reset successfully. You can now login with your new password.`,
    }
  } catch (error) {
    await session.abortTransaction()
    throw error
  } finally {
    await session.endSession()
  }
}

//TODO session related issue needs to be fixed
const verifyAccount = async (
  email: string,
  onetimeCode: string,
  requiredType: VERIFICATION_TYPE, // 1. Add this parameter
): Promise<IAuthResponse> => {
  const sanitizedEmail = getSanitizeEmail(email)

  const session = await mongoose.startSession()

  try {
    session.startTransaction()

    const user = await User.findOne({
      email: sanitizedEmail,
      status: { $ne: USER_STATUS.DELETED },
    })
      .select('+authentication')
      .session(session)

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, 'Account not found.')
    }

    if (user.status === USER_STATUS.RESTRICTED) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        'Your account has been restricted by admin, please contact support.',
      )
    }

    // 2. Fetch Verification Record
    const verification = await Verification.findOne({
      identifier: sanitizedEmail,
      type: requiredType, // Now it is context-aware
    }).session(session)

    if (!verification) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        'Invalid or expired session. Please resend OTP.',
      )
    }

    // 3. Brute Force Protection: Check Attempts
    if (verification.attempts >= Number(config.max_otp_attempts)) {
      // Optional: Logically you could also restrict the user account here
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        'Too many failed OTP attempts. Please request a new one.',
      )
    }

    // 4. Expiry Check
    if (new Date() > verification.otpExpiresAt) {
      throw new ApiError(StatusCodes.BAD_REQUEST, 'OTP has expired.')
    }

    // 5. Verify Code
    const isOtpValid = await compareOtp(onetimeCode, verification.otpHash)

    if (!isOtpValid) {
      // Increment attempts atomically
      await Verification.findByIdAndUpdate(verification._id, {
        $inc: { attempts: 1 },
      }).session(session)

      await session.commitTransaction() // Save the failed attempt count
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Invalid OTP.')
    }

    // --- LOGIC BRANCHES ---

    // A. ACCOUNT ACTIVATION
    if (verification.type === VERIFICATION_TYPE.ACCOUNT_ACTIVATION) {
      await User.findByIdAndUpdate(user._id, {
        $set: { verified: true },
      }).session(session)

      await Verification.deleteOne({
        identifier: sanitizedEmail,
        type: requiredType,
      }).session(session)

      await session.commitTransaction()

      const tokens = AuthHelper.createToken(
        user._id,
        user.role,
        user.name,
        user.email,
      )
      return authResponse(StatusCodes.OK, `Welcome, ${user.name}.`, {
        role: user.role,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      })
    }

    // B. RESET PASSWORD
    if (verification.type === VERIFICATION_TYPE.RESET_PASSWORD) {
      const resetToken = cryptoToken()

      await Token.create(
        [
          {
            token: resetToken,
            user: user._id,
            // Ensure token expires in 10-15 minutes
            expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          },
        ],
        { session },
      )

      // Clean up verification to prevent OTP reuse
      await Verification.deleteOne({
        identifier: sanitizedEmail,
        type: requiredType,
      }).session(session)

      await session.commitTransaction()

      return authResponse(
        StatusCodes.OK,
        'OTP verified. You may now reset your password.',
        {
          token: resetToken,
        },
      )
    }

    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Unknown verification type.',
    )
  } catch (error) {
    await session.abortTransaction()
    throw error
  } finally {
    await session.endSession()
  }
}

const getRefreshToken = async (token: string) => {
  try {
    // 1. Verify Token Signature
    const decodedToken = jwtHelper.verifyToken(
      token,
      config.jwt.jwt_refresh_secret as string,
    )

    const { authId, iat } = decodedToken

    // 2. Fetch User from DB (Critical for Enterprise)
    const user = await User.findById(authId).select('+authentication').lean()

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, 'User no longer exists.')
    }

    // 3. Security Check: Admin Restriction
    if (user.status === USER_STATUS.DELETED) {
      throw new ApiError(StatusCodes.FORBIDDEN, 'Account has been deleted.')
    }

    if (user.status === USER_STATUS.RESTRICTED) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        'Account restricted. Cannot refresh session.',
      )
    }

    // 4. Security Check: Password Change Invalidation
    // If password was changed after this refresh token was issued, reject it.
    if (
      user.authentication?.passwordChangedAt &&
      AuthHelper.isTokenInvalidated(user.authentication.passwordChangedAt, iat!)
    ) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        'Session expired due to password change.',
      )
    }

    // 5. Generate NEW Access Token
    // Usually, you only return a new Access Token, not a new Refresh Token (unless using rotation)
    const tokens = AuthHelper.createToken(
      user._id,
      user.role,
      user.name,
      user.email,
    )

    return {
      accessToken: tokens.accessToken,
    }
  } catch (error) {
    if (error instanceof ApiError) throw error

    if (error instanceof Error && error.name === 'TokenExpiredError') {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        'Refresh Token has expired. Please login again.',
      )
    }
    throw new ApiError(StatusCodes.FORBIDDEN, 'Invalid Refresh Token.')
  }
}

const socialLogin = async (
  appId: string,
  fcmToken: string,
): Promise<IAuthResponse> => {
  const isUserExist = await User.findOne({
    appId,
    status: { $in: [USER_STATUS.ACTIVE, USER_STATUS.RESTRICTED] },
  })
  if (!isUserExist) {
    const createdUser = await User.create({
      appId,
      fcmToken,
      status: USER_STATUS.ACTIVE,
    })
    if (!createdUser)
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create user.')
    const tokens = AuthHelper.createToken(
      createdUser._id,
      createdUser.role,
      createdUser.name,
      createdUser.email,
    )
    return authResponse(
      StatusCodes.OK,
      `Welcome ${createdUser.name} to our platform.`,
      {
        role: createdUser.role,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      },
    )
  } else {
    await User.findByIdAndUpdate(isUserExist._id, {
      $set: {
        fcmToken,
      },
    })

    const tokens = AuthHelper.createToken(
      isUserExist._id,
      isUserExist.role,
      isUserExist.name,
      isUserExist.email,
    )
    //send token to client
    return authResponse(
      StatusCodes.OK,
      `Welcome ${isUserExist.name} to our platform.`,
      {
        role: isUserExist.role,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      },
    )
  }
}

const deleteAccount = async (user: JwtPayload, password: string) => {
  const { authId } = user

  const isUserExist = await User.findById(authId).select(
    '+password +authentication',
  )

  if (!isUserExist) {
    throw new ApiError(
      StatusCodes.NOT_FOUND,
      'User not found. Failed to delete account.',
    )
  }

  if (isUserExist.status === USER_STATUS.DELETED) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'This account has already been deleted.',
    )
  }
  const {
    isRestricted,
    restrictionLeftAt,
    wrongLoginAttempts = 0,
  } = isUserExist.authentication || {}

  // 3. Brute Force Check (Check if user is currently locked out)
  if (isRestricted && restrictionLeftAt && new Date() < restrictionLeftAt) {
    const remaining = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Action blocked. Try again in ${remaining} minutes.`,
    )
  }
  const isPasswordMatched = await User.isPasswordMatched(
    password,
    isUserExist.password,
  )

  if (!isPasswordMatched) {
    const attempts = wrongLoginAttempts + 1
    const shouldLock = attempts >= Number(config.max_wrong_attempts)

    const updateQuery: any = {
      $inc: { 'authentication.wrongLoginAttempts': 1 },
      $set: { 'authentication.isRestricted': shouldLock },
    }

    if (shouldLock) {
      const lockUntil = new Date(
        Date.now() + Number(config.restriction_minutes) * 60 * 1000,
      )
      updateQuery.$set['authentication.restrictionLeftAt'] = lockUntil
    }

    await User.findByIdAndUpdate(authId, updateQuery)

    throw new ApiError(
      StatusCodes.UNAUTHORIZED,
      'Invalid password. Please provide a valid password to delete your account.',
    )
  }

  const deletionTimestamp = Math.floor(Date.now() / 1000)
  const deletedEmail = `${isUserExist.email}_deleted_${deletionTimestamp}`

  await User.findByIdAndUpdate(authId, {
    $set: {
      status: USER_STATUS.DELETED,
      email: deletedEmail,
      verified: false,
      // Clear security counters upon deletion
      'authentication.wrongLoginAttempts': 0,
      'authentication.isRestricted': false,
      'authentication.restrictionLeftAt': null,
    },
    $unset: {
      fcmToken: 1, // Remove push notification tokens
      deviceToken: 1,
    },
  })

  // 5. Success Response
  return 'Your account has been deleted successfully. We are sorry to see you go.'
}

const resendOtp = async (
  email: string,
  authType: VERIFICATION_TYPE, // Use the Enum for consistency
) => {
  const sanitizedEmail = getSanitizeEmail(email)

  console.log(email)
  // 1. Fetch User (Check if they are allowed to receive emails)
  const user = await User.findOne({
    email: sanitizedEmail,
    status: { $ne: USER_STATUS.DELETED },
  }).lean()
  if (!user) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'Account not found.')
  }

  if (user.status === USER_STATUS.RESTRICTED) {
    throw new ApiError(
      StatusCodes.FORBIDDEN,
      'Account restricted. Cannot resend OTP.',
    )
  }

  // 2. Fetch Existing Verification Record
  const existingVerification = await Verification.findOne({
    identifier: sanitizedEmail,
    type: authType,
  })

  if (!existingVerification) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'No active session found. Please try the original action again.',
    )
  }
  const OTP_RESEND_COOLDOWN = Number(config.otp_request_cooldown_seconds)
  // 3. Cooldown Logic (Time-based check)
  const secondsSinceLastRequest =
    (Date.now() - existingVerification.latestRequest.getTime()) / 1000
  if (secondsSinceLastRequest < OTP_RESEND_COOLDOWN) {
    const waitTime = Math.ceil(OTP_RESEND_COOLDOWN - secondsSinceLastRequest)
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Please wait ${waitTime} seconds before requesting a new OTP.`,
    )
  }

  // 4. Hard Limit Logic (Request count check)
  if (existingVerification.attempts >= Number(config.max_otp_attempts)) {
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      'Maximum OTP resend limit reached. Please try again after 15 minutes.',
    )
  }

  const { otp, expiresIn, hashedOtp } = await generateOtp()

  // 6. Atomic Update
  await Verification.findOneAndUpdate(
    { identifier: sanitizedEmail, type: authType },
    {
      $set: {
        otpHash: hashedOtp,
        otpExpiresAt: expiresIn,
        latestRequest: new Date(),
        attempts: 0, // Reset failed guessing attempts for the new code
        // Refresh the 15-minute TTL so the document doesn't disappear
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      },
      $inc: { requestCount: 1 }, // Increment the total requests for this session
    },
  )

  // 7. Send Email
  const resendEmailTemplate = emailTemplate.resendOtp({
    email: sanitizedEmail,
    name: user.name as string,
    otp,
    type: authType,
  })

  emailHelper.sendEmail(resendEmailTemplate).catch(err => {
    console.error('Email Resend Failed:', err)
  })

  const returnMessage = config.node_env === 'development' ? `Use this otp-${otp} to verify your account` : `A fresh OTP has been sent to your email.`
  return returnMessage
}

const changePassword = async (
  user: JwtPayload, // From Auth Middleware
  payload: IChangePassword,
) => {
  const { currentPassword, newPassword, confirmPassword } = payload
  const { authId } = user

  // 1. Basic Validation
  if (newPassword !== confirmPassword) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'New passwords do not match.')
  }

  if (currentPassword === newPassword) {
    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'New password cannot be the same as the old password.',
    )
  }

  // 2. Fetch User with security fields
  const isUserExist = await User.findById(authId).select(
    '+password +authentication',
  )
  if (!isUserExist) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'User not found.')
  }

  // 3. Admin Restriction Check
  if (isUserExist.status === USER_STATUS.RESTRICTED) {
    throw new ApiError(
      StatusCodes.FORBIDDEN,
      'Account restricted. Action denied.',
    )
  }

  // 4. Brute Force Protection (Login Lockout check)
  const {
    isRestricted,
    restrictionLeftAt,
    wrongLoginAttempts = 0,
  } = isUserExist.authentication || {}
  if (isRestricted && restrictionLeftAt && new Date() < restrictionLeftAt) {
    const remaining = Math.ceil(
      (restrictionLeftAt.getTime() - Date.now()) / 60000,
    )
    throw new ApiError(
      StatusCodes.TOO_MANY_REQUESTS,
      `Security lockout active. Try again in ${remaining} minutes.`,
    )
  }

  // 5. Verify Old Password
  const isPasswordMatched = await User.isPasswordMatched(
    currentPassword,
    isUserExist.password,
  )

  if (!isPasswordMatched) {
    // Increment wrongLoginAttempts to prevent brute-forcing this endpoint
    const attempts = wrongLoginAttempts + 1
    const shouldLock = attempts >= Number(config.max_wrong_attempts)

    await User.findByIdAndUpdate(authId, {
      $inc: { 'authentication.wrongLoginAttempts': 1 },
      $set: {
        'authentication.isRestricted': shouldLock,
        ...(shouldLock && {
          'authentication.restrictionLeftAt': new Date(
            Date.now() + Number(config.restriction_minutes) * 60 * 1000,
          ),
        }),
      },
    })

    throw new ApiError(
      StatusCodes.BAD_REQUEST,
      'The old password you provided is incorrect.',
    )
  }

  // 6. Success: Update Password
  // Setting plain text because the Mongoose pre-save hook handles hashing
  isUserExist.password = newPassword

  // Set the timestamp to invalidate current JWTs
  isUserExist.authentication.passwordChangedAt = new Date()

  // Reset security counters
  isUserExist.authentication.wrongLoginAttempts = 0
  isUserExist.authentication.isRestricted = false
  isUserExist.authentication.restrictionLeftAt = null

  await isUserExist.save()

  return {
    message:
      'Password changed successfully. Please log in again with your new credentials.',
  }
}

export const CustomAuthServices = {
  adminLogin,
  forgetPassword,
  resetPassword,
  verifyAccount,
  customLogin,
  getRefreshToken,
  socialLogin,
  deleteAccount,
  resendOtp,
  changePassword,
  createUser,
}
