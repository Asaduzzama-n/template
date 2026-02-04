import mongoose from 'mongoose'
import { IGenericErrorMessage, IGenericErrorResponse } from '../interfaces/error'

const handleCastError = (error: mongoose.Error.CastError): IGenericErrorResponse => {
  const errors: IGenericErrorMessage[] = [
    {
      path: error.path,
      message: `Invalid ${error.path}: ${error.value}`,
    },
  ]

  const statusCode = 400
  return {
    statusCode,
    message: errors[0]?.message || 'Cast Error',
    errorMessages: errors,
  }
}

export default handleCastError
