import { Request, Response, NextFunction } from 'express'
import { StatusCodes } from 'http-status-codes'
import multer, { FileFilterCallback } from 'multer'
import sharp from 'sharp'
import { randomBytes } from 'crypto'
import ApiError from '../../errors/ApiError'
import { logger, errorLogger } from '../../shared/logger'

// ─── Allowed types per field ──────────────────────────────────────────────────
const ALLOWED_TYPES: Record<string, string[]> = {
  image: ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'],
  license: ['image/jpeg', 'image/png', 'image/jpg'],
  signature: ['image/jpeg', 'image/png', 'image/jpg'],
  businessProfile: ['image/jpeg', 'image/png', 'image/jpg'],
  media: ['video/mp4', 'audio/mpeg'],
  doc: ['application/pdf'],
}

const IMAGE_FIELDS = ['image', 'license', 'signature', 'businessProfile']

// ─── Secure filename generator ────────────────────────────────────────────────
const generateFilename = (mimetype: string): string => {
  const ext = mimetype.split('/')[1].replace('jpeg', 'jpg')
  // crypto.randomBytes is cryptographically secure — Math.random() is not
  return `${Date.now()}-${randomBytes(8).toString('hex')}.${ext}`
}

// ─── Factory ──────────────────────────────────────────────────────────────────
const fileUploadHandler = () => {
  const storage = multer.memoryStorage()

  const fileFilter = (
    _req: Request,
    file: Express.Multer.File,
    cb: FileFilterCallback,
  ) => {
    const allowed = ALLOWED_TYPES[file.fieldname]
    if (!allowed) {
      return cb(
        new ApiError(
          StatusCodes.BAD_REQUEST,
          `Unsupported field: '${file.fieldname}'`,
        ),
      )
    }
    if (!allowed.includes(file.mimetype)) {
      return cb(
        new ApiError(
          StatusCodes.BAD_REQUEST,
          `Invalid file type '${file.mimetype}' for field '${file.fieldname}'. Allowed: ${allowed.join(', ')}`,
        ),
      )
    }
    cb(null, true)
  }

  const upload = multer({
    storage,
    fileFilter,
    limits: {
      fileSize: 10 * 1024 * 1024, // 10 MB
      files: 10,
    },
  }).fields([
    { name: 'image', maxCount: 5 },
    { name: 'license', maxCount: 1 },
    { name: 'signature', maxCount: 1 },
    { name: 'businessProfile', maxCount: 1 },
    { name: 'media', maxCount: 3 },
    { name: 'doc', maxCount: 3 },
  ])

  // ─── Image optimization with Sharp ─────────────────────────────────────────
  const processImages = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => {
    if (!req.files) return next()

    try {
      for (const field of IMAGE_FIELDS) {
        const files = (req.files as Record<string, Express.Multer.File[]>)[
          field
        ]
        if (!files) continue

        for (const file of files) {
          if (!file.mimetype.startsWith('image/')) continue

          try {
            // Build Sharp pipeline — pick ONE output format, never chain conflicting formats
            const isPng = file.mimetype === 'image/png'
            const isWebp = file.mimetype === 'image/webp'

            const pipeline = sharp(file.buffer).resize({
              width: 1024,
              withoutEnlargement: true, // don't upscale small images
            })

            if (isPng) {
              file.buffer = await pipeline.png({ quality: 80 }).toBuffer()
            } else if (isWebp) {
              file.buffer = await pipeline.webp({ quality: 80 }).toBuffer()
            } else {
              // JPEG (and jpg)
              file.buffer = await pipeline.jpeg({ quality: 80 }).toBuffer()
            }

            // Assign secure filename for downstream use
            file.originalname = generateFilename(file.mimetype)
          } catch (sharpErr) {
            errorLogger.error(
              `Image optimization failed for field '${field}':`,
              sharpErr,
            )
            // Degraded gracefully — continue with original buffer
          }
        }
      }

      next()
    } catch (error) {
      next(
        new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          'Image processing failed',
        ),
      )
    }
  }

  return (req: Request, res: Response, next: NextFunction) => {
    upload(req, res, err => {
      if (err) {
        if (err instanceof multer.MulterError) {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return next(
              new ApiError(
                StatusCodes.BAD_REQUEST,
                'File too large. Maximum size is 10 MB.',
              ),
            )
          }
          if (err.code === 'LIMIT_FILE_COUNT') {
            return next(
              new ApiError(
                StatusCodes.BAD_REQUEST,
                'Too many files uploaded.',
              ),
            )
          }
        }
        return next(err)
      }
      processImages(req, res, next)
    })
  }
}

export default fileUploadHandler
