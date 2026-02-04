import { Request, Response } from 'express'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import { StatusCodes } from 'http-status-codes'
import { NotificationServices } from './notifications.service'
import pick from '../../../shared/pick'
import { paginationFields } from '../../../interfaces/pagination'

const getMyNotifications = catchAsync(async (req: Request, res: Response) => {
  const paginationOptions = pick(req.query, paginationFields)
  const result = await NotificationServices.getNotifications(req.user!, paginationOptions)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Notifications retrieved successfully',
    data: result,
  })
})

const updateNotification = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params
  const result = await NotificationServices.readNotification(req.user!, id)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Notification marked as read',
    data: result,
  })
})

const updateAllNotifications = catchAsync(async (req: Request, res: Response) => {
  const result = await NotificationServices.readAllNotifications(req.user!)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'All notifications marked as read',
    data: result,
  })
})

export const NotificationController = {
  getMyNotifications,
  updateNotification,
  updateAllNotifications,
}

