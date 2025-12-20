import { Model, Types } from 'mongoose';

export enum TypeEnum {
  ACCOUNT_ACTIVATION = 'account_activation',
  RESET_PASSWORD = 'reset_password',
}


export interface IVerification {
  _id?: Types.ObjectId;
  type: TypeEnum;
  identifier:string
  otpHash: string;
  latestRequest: Date;
  expiresAt: Date;
  attempts: number;
  createdAt?: Date;
  updatedAt?: Date;
}

export type VerificationModel = Model<IVerification, {}, {}>;
