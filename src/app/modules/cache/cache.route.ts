import express from 'express'
import { CacheController } from './cache.controller'
import auth from '../../middleware/auth'
import { USER_ROLES } from '../../../enum/user'

const router = express.Router()

// Cache statistics (Admin only)
router.get('/stats', auth(USER_ROLES.ADMIN), CacheController.getStats)

// Reset cache statistics (Admin only)
router.post('/stats/reset', auth(USER_ROLES.ADMIN), CacheController.resetStats)

// Get all cached keys (Admin only)
router.get('/keys', auth(USER_ROLES.ADMIN), CacheController.getCachedKeys)

// Clear all cache (Admin only)
router.delete('/clear', auth(USER_ROLES.ADMIN), CacheController.clearCache)

// Redis health check (public for load balancer)
router.get('/redis/health', CacheController.redisHealth)

export const CacheRoutes = router
