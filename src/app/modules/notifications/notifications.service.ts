import { StatusCodes } from 'http-status-codes'
import ApiError from '../../../errors/ApiError'
import { JwtPayload } from 'jsonwebtoken'
import { Types } from 'mongoose'
import { Notification } from './notifications.model'
import { IPaginationOptions } from '../../../interfaces/pagination'
import { paginationHelper } from '../../../helpers/paginationHelper'



const getNotifications = async (user: JwtPayload, paginationOptions: IPaginationOptions) => {
  const { page, limit, skip, sortBy, sortOrder } = paginationHelper.calculatePagination(paginationOptions)
  const [result, total, unreadCount] = await Promise.all([
    Notification.find({ to: user.authId })
      // Select only safe fields — never expose full user documents
      .populate('from', 'name profile _id')
      .populate('to', 'name _id')
      .skip(skip)
      .limit(limit)
      .sort({ [sortBy]: sortOrder })
      .lean(),
    Notification.countDocuments({ to: user.authId }),
    Notification.countDocuments({ to: user.authId, isRead: false }),
  ])

  return {
    meta: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      unreadCount,
    },
    data: result,
  }
}

const readNotification = async (id: string) => {
 try {
    await Notification.findByIdAndUpdate(
      new Types.ObjectId(id),
      { isRead: true },
      { new: true },
    )
    return 'Notification read successfully'
 } catch (error) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to mark notification as read')
 }
}

const readAllNotifications = async (user: JwtPayload) => {
 try {
    await Notification.updateMany({ to: user.authId }, { isRead: true })
    return 'All notifications read successfully'
 } catch (error) {
    throw new ApiError(StatusCodes.BAD_REQUEST, 'Failed to mark all notifications as read')
 }
}

export const NotificationServices = {
  getNotifications,
  readNotification,
  readAllNotifications,
}
