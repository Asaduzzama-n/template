import { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import config from '../../config'

/**
 * Security Headers Middleware using Helmet
 * 
 * Configures various HTTP headers for security:
 * - Content-Security-Policy
 * - Strict-Transport-Security
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - X-XSS-Protection
 * - Referrer-Policy
 */
export const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Adjust based on your frontend needs
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https:", "wss:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: config.node_env === 'production' ? [] : null,
        },
    },
    crossOriginEmbedderPolicy: false, // Disable if using external resources
    crossOriginResourcePolicy: { policy: "cross-origin" }, // Allow cross-origin for API
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
})

/**
 * Prevent parameter pollution
 * Removes duplicate query parameters
 */
export const preventParameterPollution = (req: Request, res: Response, next: NextFunction) => {
    if (req.query) {
        for (const key in req.query) {
            if (Array.isArray(req.query[key])) {
                // Take only the last value if multiple values are provided
                req.query[key] = req.query[key][req.query[key].length - 1]
            }
        }
    }
    next()
}

/**
 * Sanitize request body to prevent NoSQL injection
 * Removes $ and . from object keys
 */
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
    const sanitize = (obj: any): any => {
        if (obj === null || typeof obj !== 'object') {
            return obj
        }

        if (Array.isArray(obj)) {
            return obj.map(sanitize)
        }

        const sanitized: any = {}
        for (const key of Object.keys(obj)) {
            // Skip keys starting with $ (MongoDB operators)
            if (key.startsWith('$')) {
                continue
            }

            // Replace dots in keys (MongoDB path traversal)
            const safeKey = key.replace(/\./g, '_')
            sanitized[safeKey] = sanitize(obj[key])
        }

        return sanitized
    }

    if (req.body) {
        req.body = sanitize(req.body)
    }
    if (req.query) {
        req.query = sanitize(req.query)
    }
    if (req.params) {
        req.params = sanitize(req.params)
    }

    next()
}

/**
 * Block suspicious user agents
 */
export const blockSuspiciousUserAgents = (req: Request, res: Response, next: NextFunction): void => {
    const userAgent = req.get('User-Agent') || ''

    const suspiciousPatterns = [
        /sqlmap/i,
        /nikto/i,
        /nessus/i,
        /nmap/i,
        /masscan/i,
        /havij/i,
    ]

    if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
        res.status(403).json({
            success: false,
            message: 'Access denied',
        })
        return
    }

    next()
}

/**
 * Validate Content-Type for POST/PUT/PATCH requests
 */
export const validateContentType = (req: Request, res: Response, next: NextFunction): void => {
    const methodsWithBody = ['POST', 'PUT', 'PATCH']

    if (methodsWithBody.includes(req.method)) {
        const contentType = req.get('Content-Type')

        // Skip if no body expected
        if (!contentType && Object.keys(req.body || {}).length === 0) {
            next()
            return
        }

        const validTypes = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
        ]

        const isValid = validTypes.some(type => contentType?.includes(type))

        if (!isValid) {
            res.status(415).json({
                success: false,
                message: 'Unsupported Media Type',
            })
            return
        }
    }

    next()
}

/**
 * Combine all security middlewares
 */
export const securityMiddleware = [
    securityHeaders,
    preventParameterPollution,
    sanitizeInput,
    blockSuspiciousUserAgents,
    validateContentType,
]
