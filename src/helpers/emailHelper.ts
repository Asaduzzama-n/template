import nodemailer from 'nodemailer'
import config from '../config'
import { errorLogger, logger } from '../shared/logger'
import { ISendEmail } from '../interfaces/email'
import { addJob, QUEUE_NAMES, JOB_TYPES } from '../queues'
import { IEmailJobData } from '../queues/workers/emailWorker'

/**
 * Nodemailer transporter for direct sending (used by workers)
 */
const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: Number(config.email.port),
  secure: Number(config.email.port) === 465,
  auth: {
    user: config.email.user,
    pass: config.email.pass,
  },
})

/**
 * Send email directly (synchronous - blocks until sent)
 * Use this only when you absolutely need to wait for the email to be sent
 * 
 * @deprecated Use queueEmail() for better performance
 */
const sendEmail = async (values: ISendEmail): Promise<boolean> => {
  try {
    const info = await transporter.sendMail({
      from: `"Express-Craft" <${config.email.from}>`,
      to: values.to,
      subject: values.subject,
      html: values.html,
    })

    logger.info('Email sent successfully', {
      to: values.to,
      subject: values.subject,
      messageId: info.messageId
    })
    return true
  } catch (error: any) {
    errorLogger.error('Failed to send email', {
      to: values.to,
      subject: values.subject,
      error: error.message
    })
    return false
  }
}

/**
 * Queue email for background sending (non-blocking)
 * This is the preferred method for sending emails
 * 
 * @param values - Email data
 * @param options - Optional job options
 * @returns Job ID
 */
const queueEmail = async (
  values: ISendEmail,
  options?: {
    priority?: number
    delay?: number
  }
): Promise<string> => {
  const jobData: IEmailJobData = {
    to: values.to,
    subject: values.subject,
    html: values.html,
    from: `"Express-Craft" <${config.email.from}>`,
  }

  const job = await addJob(
    QUEUE_NAMES.EMAIL,
    JOB_TYPES.EMAIL.SEND_EMAIL,
    jobData,
    options
  )

  logger.debug('Email queued for sending', {
    jobId: job.id,
    to: values.to,
    subject: values.subject,
  })

  return job.id!
}

/**
 * Queue OTP email with high priority
 */
const queueOtpEmail = async (values: ISendEmail): Promise<string> => {
  return queueEmail(values, { priority: 1 }) // High priority
}

/**
 * Queue welcome email
 */
const queueWelcomeEmail = async (values: ISendEmail): Promise<string> => {
  return queueEmail(values, { priority: 5 }) // Normal priority
}

/**
 * Queue password reset email with high priority
 */
const queuePasswordResetEmail = async (values: ISendEmail): Promise<string> => {
  return queueEmail(values, { priority: 1 }) // High priority
}

export const emailHelper = {
  sendEmail,        // Direct send (deprecated for most use cases)
  queueEmail,       // Preferred: queue for background processing
  queueOtpEmail,
  queueWelcomeEmail,
  queuePasswordResetEmail,
}
