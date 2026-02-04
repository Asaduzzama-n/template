import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import { IContact, IFaq, IPublic } from './public.interface'
import { Faq, Public } from './public.model'
import { User } from '../user/user.model'
import { emailHelper } from '../../../helpers/emailHelper'
import { logger } from '../../../shared/logger'
import * as entities from 'entities'
import { redisHelper } from '../../../helpers/redisHelper'
import { RedisKeys } from '../../../enum/redis.keys'

const createPublic = async (payload: IPublic) => {
  const result = await Public.findOneAndUpdate(
    { type: payload.type },
    { $set: { content: payload.content } },
    { new: true, upsert: true },
  )

  if (!result) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to save public content')
  }

  // Update Cache
  const cacheKey =
    payload.type === 'terms-and-condition'
      ? RedisKeys.TERMS_AND_CONDITION
      : RedisKeys.PRIVACY_POLICY
  await redisHelper.set(cacheKey, JSON.stringify(result))

  return `${payload.type} saved successfully`
}

const getAllPublics = async (type: string) => {
  const cacheKey =
    type === 'terms-and-condition'
      ? RedisKeys.TERMS_AND_CONDITION
      : RedisKeys.PRIVACY_POLICY

  // Try Cache
  const cachedData = await redisHelper.get(cacheKey)
  if (cachedData) {
    return JSON.parse(cachedData)
  }

  // Fallback to DB
  const result = await Public.findOne({ type }).lean()

  if (result) {
    await redisHelper.set(cacheKey, JSON.stringify(result))
  }

  return result || null
}

const deletePublic = async (id: string) => {
  const result = await Public.findByIdAndDelete(id)
  if (!result) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'Public content not found')
  }
  return result
}

const createContact = async (payload: IContact) => {
  try {
    const admin = await User.findOne({ role: 'admin' })

    if (!admin || !admin.email) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        'Admin user not found',
      )
    }

    // Escape user input to prevent XSS in emails
    const safeName = entities.encodeHTML(payload.name)
    const safeEmail = entities.encodeHTML(payload.email)
    const safePhone = entities.encodeHTML(payload.phone)
    const safeCountry = entities.encodeHTML(payload.country)
    const safeMessage = entities.encodeHTML(payload.message)

    // Send email notification to admin
    const emailData = {
      to: admin.email,
      subject: 'New Contact Form Submission',
      html: `
        <h1>New Contact Form Submission</h1>
        <p>You have received a new message from the contact form:</p>
        <ul>
          <li><strong>Name:</strong> ${safeName}</li>
          <li><strong>Email:</strong> ${safeEmail}</li>
          <li><strong>Phone:</strong> ${safePhone}</li>
          <li><strong>Country:</strong> ${safeCountry}</li>
        </ul>
        <h2>Message:</h2>
        <p>${safeMessage}</p>
        <p>You can respond directly to the sender by replying to: ${safeEmail}</p>
      `,
    }

    emailHelper.sendEmail(emailData)

    // Send confirmation email to the user
    const userEmailData = {
      to: payload.email,
      subject: 'Thank you for contacting us',
      html: `
        <h1>Thank You for Contacting Us</h1>
        <p>Dear ${safeName},</p>
        <p>We have received your message and will get back to you as soon as possible.</p>
        <p>Here's a copy of your message:</p>
        <p><em>${safeMessage}</em></p>
        <p>Best regards,<br>The Team</p>
      `,
    }

    emailHelper.sendEmail(userEmailData)

    return {
      message: 'Contact form submitted successfully',
    }
  } catch (error) {
    logger.error('createContact error:', error)
    if (error instanceof ApiError) throw error
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Failed to submit contact form',
    )
  }
}

const createFaq = async (payload: IFaq) => {
  const result = await Faq.create(payload)
  if (!result)
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create Faq')

  // Invalidate FAQ cache
  await redisHelper.del(RedisKeys.FAQ)

  return result
}

const getAllFaqs = async () => {
  // Try Cache
  const cachedData = await redisHelper.get(RedisKeys.FAQ)
  if (cachedData) {
    return JSON.parse(cachedData)
  }

  // Fallback to DB
  const result = await Faq.find({}).lean()

  if (result && result.length > 0) {
    await redisHelper.set(RedisKeys.FAQ, JSON.stringify(result))
  }

  return result || []
}

const getSingleFaq = async (id: string) => {
  const result = await Faq.findById(id).lean()
  if (!result) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'FAQ not found')
  }
  return result
}

const updateFaq = async (id: string, payload: Partial<IFaq>) => {
  const result = await Faq.findByIdAndUpdate(
    id,
    { $set: payload },
    { new: true },
  )

  if (!result) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'FAQ not found')
  }

  // Invalidate FAQ cache
  await redisHelper.del(RedisKeys.FAQ)

  return result
}

const deleteFaq = async (id: string) => {
  const result = await Faq.findByIdAndDelete(id)
  if (!result) {
    throw new ApiError(StatusCodes.NOT_FOUND, 'FAQ not found')
  }

  // Invalidate FAQ cache
  await redisHelper.del(RedisKeys.FAQ)

  return result
}

export const PublicServices = {
  createPublic,
  getAllPublics,
  deletePublic,
  createContact,
  createFaq,
  getAllFaqs,
  getSingleFaq,
  updateFaq,
  deleteFaq,
}

