import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import config from '../../../config'
import { Verification } from './verification.model'
import { VERIFICATION_TYPE } from './verification.interface'
import { generateOtp, compareOtp } from '../../../utils/crypto'
import { ClientSession } from 'mongoose'

// ==================== RATE LIMITING UTILITIES ====================

/**
 * Validates OTP request limits and cooldown
 * @throws ApiError if cooldown not elapsed or request limit exceeded
 */
const validateOtpRequest = async (
    identifier: string,
    type: VERIFICATION_TYPE,
): Promise<void> => {
    const existing = await Verification.findOne({ identifier, type }).lean()

    if (!existing) return

    // Cooldown check
    if (existing.latestRequest) {
        const secondsSinceLast = (Date.now() - existing.latestRequest.getTime()) / 1000
        if (secondsSinceLast < Number(config.otp_request_cooldown_seconds)) {
            const waitTime = Math.ceil(Number(config.otp_request_cooldown_seconds) - secondsSinceLast)
            throw new ApiError(
                StatusCodes.TOO_MANY_REQUESTS,
                `Please wait ${waitTime} seconds before requesting a new OTP.`,
            )
        }
    }

    // Request limit check
    if (existing.requestCount >= Number(config.max_otp_request_allowed || 5)) {
        throw new ApiError(
            StatusCodes.TOO_MANY_REQUESTS,
            'Maximum OTP limit reached. Please try again in 15 minutes.',
        )
    }
}

// ==================== OTP MANAGEMENT ====================

/**
 * Creates or updates a verification record with proper rate limiting
 * Handles both new verifications and OTP resends with atomic operations
 */
const upsertVerification = async (
    identifier: string,
    type: VERIFICATION_TYPE,
): Promise<{ otp: string; expiresIn: Date }> => {
    const { otp, expiresIn, hashedOtp } = await generateOtp()

    await Verification.findOneAndUpdate(
        { identifier, type },
        {
            $set: {
                otpHash: hashedOtp,
                otpExpiresAt: expiresIn,
                latestRequest: new Date(),
                attempts: 0,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000),
            },
            $inc: { requestCount: 1 },
        },
        { upsert: true, new: true },
    )

    return { otp, expiresIn }
}

/**
 * Creates initial verification record for new user registration
 * Use this ONLY during user signup within a transaction
 */
const createInitialVerification = async (
    identifier: string,
    type: VERIFICATION_TYPE,
    session?: ClientSession,
): Promise<{ otp: string; expiresIn: Date }> => {
    const { otp, expiresIn, hashedOtp } = await generateOtp()

    const doc = {
        identifier,
        type,
        otpHash: hashedOtp,
        otpExpiresAt: expiresIn,
        latestRequest: new Date(),
        attempts: 0,
        requestCount: 1,
    }

    if (session) {
        await Verification.create([doc], { session })
    } else {
        await Verification.create(doc)
    }

    return { otp, expiresIn }
}

// ==================== OTP VERIFICATION ====================

/**
 * Validates OTP attempts and expiry before checking the code
 * @returns verification document if valid
 * @throws ApiError if max attempts exceeded or expired
 */
const getAndValidateVerification = async (
    identifier: string,
    type: VERIFICATION_TYPE,
    session?: ClientSession,
) => {
    const query = Verification.findOne({ identifier, type })
    const verification = session ? await query.session(session) : await query

    if (!verification) {
        throw new ApiError(
            StatusCodes.BAD_REQUEST,
            'Invalid or expired session. Please resend OTP.',
        )
    }

    // Brute Force Protection: Check Attempts
    if (verification.attempts >= Number(config.max_otp_attempts)) {
        throw new ApiError(
            StatusCodes.TOO_MANY_REQUESTS,
            'Too many failed OTP attempts. Please request a new one.',
        )
    }

    // Expiry Check
    if (new Date() > verification.otpExpiresAt) {
        throw new ApiError(StatusCodes.BAD_REQUEST, 'OTP has expired.')
    }

    return verification
}

/**
 * Verifies OTP code and handles attempt counting
 * @returns true if OTP is valid
 * @throws ApiError if OTP is invalid (also increments attempt count)
 */
const verifyOtp = async (
    identifier: string,
    type: VERIFICATION_TYPE,
    otp: string,
    session?: ClientSession,
): Promise<boolean> => {
    const verification = await getAndValidateVerification(identifier, type, session)

    const isOtpValid = await compareOtp(otp, verification.otpHash)

    if (!isOtpValid) {
        // Increment attempts atomically
        const updateQuery = Verification.findByIdAndUpdate(verification._id, {
            $inc: { attempts: 1 },
        })
        if (session) {
            await updateQuery.session(session)
        } else {
            await updateQuery
        }

        throw new ApiError(StatusCodes.BAD_REQUEST, 'Invalid OTP.')
    }

    return true
}

// ==================== CLEANUP ====================

/**
 * Deletes a verification record after successful verification
 */
const deleteVerification = async (
    identifier: string,
    type: VERIFICATION_TYPE,
    session?: ClientSession,
): Promise<void> => {
    const query = Verification.deleteOne({ identifier, type })
    if (session) {
        await query.session(session)
    } else {
        await query
    }
}

export const VerificationService = {
    // Rate Limiting
    validateOtpRequest,

    // OTP Management
    upsertVerification,
    createInitialVerification,

    // Verification
    getAndValidateVerification,
    verifyOtp,

    // Cleanup
    deleteVerification,
}