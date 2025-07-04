import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import { JwtPayload } from 'jsonwebtoken'
import { Types } from 'mongoose'
import { Notification } from './notifications.model'

const getNotifications = (user: JwtPayload) => {
  const result = Notification.find({ user: user.authId })
    .populate('to', 'name image')
    .populate('from', 'name image')
    .lean()
  return result
}

const readNotification = async (id: string) => {
  const result = await Notification.findByIdAndUpdate(
    new Types.ObjectId(id),
    { isRead: true },
    { new: true },
  )
  return result
}

const readAllNotifications = (user: JwtPayload) => {
  const result = Notification.updateMany({ user: user.authId }, { isRead: true })
  return result
}

export const NotificationServices = {
  getNotifications,
  readNotification,
  readAllNotifications,
}
