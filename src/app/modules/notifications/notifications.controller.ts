import { Request, Response } from 'express'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import { StatusCodes } from 'http-status-codes'
import { NotificationServices } from './notifications.service'
import pick from '../../../shared/pick'
import { paginationFields } from '../../../interfaces/pagination'

const getMyNotifications = catchAsync(async (req: Request, res: Response) => {

  const pagination = pick(req.query, paginationFields)
  const result = await NotificationServices.getNotifications(req.user!, pagination)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Notifications retrieved successfully',
    data: result,
  })

})
const updateNotification = catchAsync(async (req: Request, res: Response) => {
  const notificationId = req.params.id
  const result = await NotificationServices.readNotification(notificationId)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Notifications updated successfully',
    data: result,
  })
})

const updateAllNotifications = catchAsync(async (req: Request, res: Response) => {
  const result = await NotificationServices.readAllNotifications(req.user!)
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Notifications updated successfully',
    data: result,
  })
})

export const NotificationController = {
  getMyNotifications,
  updateNotification,
  updateAllNotifications,
}
