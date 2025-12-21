import { Model, Types } from 'mongoose';

export type IToken = {
  user: Types.ObjectId;
  token: string;
  expiresAt: Date;
};

export type TokenModel = Model<IToken>;
