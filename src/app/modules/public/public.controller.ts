import { Request, Response } from 'express'
import { PublicServices } from './public.service'
import catchAsync from '../../../shared/catchAsync'
import sendResponse from '../../../shared/sendResponse'
import { StatusCodes } from 'http-status-codes'

const createPublic = catchAsync(async (req: Request, res: Response) => {
  const result = await PublicServices.createPublic(req.body)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: result,
    data: null,
  })
})

const getAllPublics = catchAsync(async (req: Request, res: Response) => {
  const { type } = req.params
  const result = await PublicServices.getAllPublics(type)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Public content retrieved successfully',
    data: result,
  })
})

const deletePublic = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params
  const result = await PublicServices.deletePublic(id)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Public content deleted successfully',
    data: result,
  })
})

const createContact = catchAsync(async (req: Request, res: Response) => {
  const result = await PublicServices.createContact(req.body)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'Thank you for contacting us. We will get back to you soon.',
    data: result,
  })
})

const createFaq = catchAsync(async (req: Request, res: Response) => {
  const result = await PublicServices.createFaq(req.body)

  sendResponse(res, {
    statusCode: StatusCodes.CREATED,
    success: true,
    message: 'FAQ created successfully',
    data: result,
  })
})

const updateFaq = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params
  const result = await PublicServices.updateFaq(id, req.body)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'FAQ updated successfully',
    data: result,
  })
})

const getSingleFaq = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params
  const result = await PublicServices.getSingleFaq(id)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'FAQ retrieved successfully',
    data: result,
  })
})

const getAllFaqs = catchAsync(async (req: Request, res: Response) => {
  const result = await PublicServices.getAllFaqs()

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'FAQs retrieved successfully',
    data: result,
  })
})

const deleteFaq = catchAsync(async (req: Request, res: Response) => {
  const { id } = req.params
  const result = await PublicServices.deleteFaq(id)

  sendResponse(res, {
    statusCode: StatusCodes.OK,
    success: true,
    message: 'FAQ deleted successfully',
    data: result,
  })
})

export const PublicController = {
  createPublic,
  getAllPublics,
  deletePublic,
  createContact,
  createFaq,
  updateFaq,
  getSingleFaq,
  getAllFaqs,
  deleteFaq,
}

