import { Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import { MaintenanceService } from './maintenance.service'

const purgeDeletedUsers = catchAsync(async (req: Request, res: Response) => {
  const { days = 30 } = req.query
  const purgedCount = await MaintenanceService.purgeOldDeletedUsers(Number(days))
  
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: `System purge complete. Permanently removed ${purgedCount} old user records.`,
    data: { purgedCount },
  })
})

const clearAuthCache = catchAsync(async (req: Request, res: Response) => {
  const clearedCount = await MaintenanceService.clearAuthCache()
  
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: `Auth cache cleared. ${clearedCount} security entries removed from Redis.`,
    data: { clearedCount },
  })
})

const getStats = catchAsync(async (req: Request, res: Response) => {
  const stats = await MaintenanceService.getStorageStats()
  
  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'System storage statistics retrieved successfully.',
    data: stats,
  })
})

export const MaintenanceController = {
  purgeDeletedUsers,
  clearAuthCache,
  getStats,
}
