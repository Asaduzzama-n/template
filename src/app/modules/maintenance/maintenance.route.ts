import express from 'express'
import { MaintenanceController } from './maintenance.controller'
import auth from '../../middleware/auth'
import { USER_ROLES } from '../../../enum/user'

const router = express.Router()

router.get(
  '/stats',
  auth(USER_ROLES.ADMIN),
  MaintenanceController.getStats,
)

router.post(
  '/purge-deleted-users',
  auth(USER_ROLES.ADMIN),
  MaintenanceController.purgeDeletedUsers,
)

router.post(
  '/clear-auth-cache',
  auth(USER_ROLES.ADMIN),
  MaintenanceController.clearAuthCache,
)

export const MaintenanceRoutes = router
