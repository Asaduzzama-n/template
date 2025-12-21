import { Model, Types } from 'mongoose';

export enum VERIFICATION_TYPE {
  ACCOUNT_ACTIVATION = 'account_activation',
  RESET_PASSWORD = 'reset_password',
}


export interface IVerification {
  _id?: Types.ObjectId;
  type: VERIFICATION_TYPE;
  identifier:string
  otpHash: string;
  latestRequest: Date;
  otpExpiresAt: Date;
  attempts: number;
  requestCount:number;
  expiresAt:Date;
  createdAt?: Date;
  updatedAt?: Date;
}

export type VerificationModel = Model<IVerification, {}, {}>;
