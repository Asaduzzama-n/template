import {
  DeleteObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3'
import config from '../../config'
import { logger } from '../../shared/logger'
import ApiError from '../../errors/ApiError'
import { StatusCodes } from 'http-status-codes'
import sharp from 'sharp'

const s3Client = new S3Client({
  endpoint: config.rustfs.endpoint,
  region: config.rustfs.region,
  credentials: {
    accessKeyId: config.rustfs.access_key!,
    secretAccessKey: config.rustfs.secret_key!,
  },
  forcePathStyle: true, // Required for most S3-compatible storage like RustFS/MinIO
})

const getPublicUri = (fileKey: string): string => {
  // If RustFS is behind a proxy or has a public URL, this might need adjustment
  return `${config.rustfs.endpoint}/${config.rustfs.bucket}/${fileKey}`
}

const uploadToRustFS = async (
  file: Express.Multer.File,
  folder: string,
): Promise<string> => {
  const extension = file.originalname.split('.').pop()
  const fileKey = `${folder}/${Date.now()}-${Math.random().toString(36).slice(2)}.${extension}`

  try {
    let body: Buffer = file.buffer

    // Optimize image if it's an image
    if (file.mimetype.startsWith('image/')) {
      body = await sharp(file.buffer)
        .resize(1024, 1024, { fit: 'inside', withoutEnlargement: true })
        .toBuffer()
    }

    const params = {
      Bucket: config.rustfs.bucket,
      Key: fileKey,
      Body: body,
      ContentType: file.mimetype,
    }

    const command = new PutObjectCommand(params)
    await s3Client.send(command)
    return getPublicUri(fileKey)
  } catch (error) {
    logger.error('Error uploading to RustFS:', error)
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Failed to upload file to RustFS',
    )
  }
}

const deleteFromRustFS = async (fileKey: string): Promise<void> => {
  const params = {
    Bucket: config.rustfs.bucket,
    Key: fileKey,
  }

  try {
    const command = new DeleteObjectCommand(params)
    await s3Client.send(command)
  } catch (error) {
    logger.error('Error deleting from RustFS:', error)
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      'Failed to delete file from RustFS',
    )
  }
}

const uploadMultipleToRustFS = async (
  files: Express.Multer.File[],
  folder: string,
): Promise<string[]> => {
  const uploadPromises = files.map(file => uploadToRustFS(file, folder))
  const results = await Promise.allSettled(uploadPromises)

  return results
    .filter(
      (result): result is PromiseFulfilledResult<string> =>
        result.status === 'fulfilled',
    )
    .map(result => result.value)
}

export const RustFSHelper = {
  uploadToRustFS,
  uploadMultipleToRustFS,
  deleteFromRustFS,
}
