import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import { IContact, IFaq, IPublic } from './public.interface'
import { Faq, Public } from './public.model'

import { User } from '../user/user.model'
import { emailHelper } from '../../../helpers/emailHelper'
import { redisClient } from '../../../helpers/redis'
import { RedisKeys } from '../../../enum/redis.keys'
import { emailQueue } from '../../../helpers/bull-mq-producer'


const createPublic = async (payload: IPublic) => {

  const isExist = await Public.findOne({
    type: payload.type,
  })
  if (isExist) {
    await Public.findByIdAndUpdate(
      isExist._id,
      {
        $set: {
          content: payload.content,
        },
      },
      {
        new: true,
      },
    )
    //store the result in redis
    redisClient.del(payload.type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`)
    redisClient.setex(payload.type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`, 60 * 60 * 24, JSON.stringify(isExist))
  } else {
    const result = await Public.create(payload)
    if (!result)
      throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to create Public')
    //store the result in redis
    redisClient.del(payload.type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`)
    redisClient.setex(payload.type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`, 60 * 60 * 24, JSON.stringify(result))
  }

  return `${payload.type} created successfully}`
}

const getAllPublics = async (
  type: 'privacy-policy' | 'terms-and-condition',
) => {
  const cachedResult = await redisClient.get(type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`)
  if (cachedResult) {
    return JSON.parse(cachedResult)
  }
  const result = await Public.findOne({ type: type }).lean()
  //store the result in redis
  redisClient.setex(type === 'privacy-policy' ? `public:${RedisKeys.PRIVACY_POLICY}` : `public:${RedisKeys.TERMS_AND_CONDITION}`, 60 * 60 * 24, JSON.stringify(result))
  return result || null
}

const deletePublic = async (id: string) => {
  const result = await Public.findByIdAndDelete(id)
  return result
}

const createContact = async (payload: IContact) => {
  try {
    // Find admin user to send notification
    const admin = await User.findOne({ role: 'admin' })

    if (!admin || !admin.email) {
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        'Admin user not found',
      )
    }

    // Send email notification to admin
    const emailData = {
      to: admin.email,
      subject: 'New Contact Form Submission',
      html: `
        <h1>New Contact Form Submission</h1>
        <p>You have received a new message from the contact form:</p>
        <ul>
          <li><strong>Name:</strong> ${payload.name}</li>
          <li><strong>Email:</strong> ${payload.email}</li>
          <li><strong>Phone:</strong> ${payload.phone}</li>
          <li><strong>Country:</strong> ${payload.country}</li>
        </ul>
        <h2>Message:</h2>
        <p>${payload.message}</p>
        <p>You can respond directly to the sender by replying to: ${payload.email}</p>
      `,
    }

    emailQueue.add('emails', emailData)

    // Send confirmation email to the user
    const userEmailData = {
      to: payload.email,
      subject: 'Thank you for contacting us',
      html: `
        <h1>Thank You for Contacting Us</h1>
        <p>Dear ${payload.name},</p>
        <p>We have received your message and will get back to you as soon as possible.</p>
        <p>Here's a copy of your message:</p>
        <p><em>${payload.message}</em></p>
        <p>Best regards,<br>The Healthcare and Financial Consultants Team</p>
      `,
    }

    emailQueue.add('emails', userEmailData)

    return {
      message: 'Contact form submitted successfully',
    }
  } catch (error) {
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
  redisClient.del(`public:${RedisKeys.FAQ}`)
  return result 
}

const getAllFaqs = async () => {
  const cachedResult = await redisClient.get(`public:${RedisKeys.FAQ}`)
  if (cachedResult) {
    return JSON.parse(cachedResult)
  }
  const result = await Faq.find({})
  redisClient.setex(`public:${RedisKeys.FAQ}`, 60 * 60 * 24, JSON.stringify(result))
  return result || []
}

const getSingleFaq = async (id: string) => {
  const result = await Faq.findById(id)
  return result || null
}

const updateFaq = async (id: string, payload: Partial<IFaq>) => {
  const result = await Faq.findByIdAndUpdate(
    id,
    { $set: payload },
    {
      new: true,
    },
  )
  redisClient.del(`public:${RedisKeys.FAQ}`)
  return result
}

const deleteFaq = async (id: string) => {
  const result = await Faq.findByIdAndDelete(id)
  redisClient.del(`public:${RedisKeys.FAQ}`)
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
