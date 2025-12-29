/* eslint-disable @typescript-eslint/no-explicit-any */
import { Model } from 'mongoose';
export enum UserRole {
  super_admin = 'super_admin',
  admin = 'admin',
  user = 'user',
  customer = 'customer',
}
export enum status {
  pending = 'pending',
  active = 'active',
  blocked = 'blocked',
}

export enum Gender {
  Male = 'Male',
  Female = 'Female',
}
interface Verification {
  otp: string | number;
  expiresAt: Date;
  status: boolean;
}
interface image {
  id: string | number;
  url: string;
}
export interface TUser {
  [x: string]: any;
  id?: string;
  email: string;
  password: string;
  name: string;
  phoneNumber: string;
  gender: Gender;
  image: image;
  needsPasswordChange: boolean;
  passwordChangedAt?: Date;
  role: UserRole;
  status?: status;
  isVerified: boolean;
  isActive: boolean;
  isDeleted: boolean;
  verification: Verification;
  accountType?: 'custom' | 'google';
  countryCode: string;
  fcmToken?: string;
}

export interface UserModel extends Model<TUser> {
  isUserExist(email: string): Promise<TUser>;
  isUserExistByNumber(countryCode: string, phoneNumber: string): Promise<TUser>;
  IsUserExistbyId(id: string): Promise<TUser>;
  isPasswordMatched(
    plainTextPassword: string,
    hashedPassword: string,
  ): Promise<boolean>;
}
