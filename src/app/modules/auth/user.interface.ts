/* eslint-disable @typescript-eslint/no-explicit-any */
export type QueryObject = {
  [key: string]: any;
};

export type Tlogin = {
  email?: string;
  countryCode?: string;
  phoneNumber?: string;
  password: string;
  fcmToken: string;
};
export type TchangePassword = {
  oldPassword: string;
  newPassword: string;
  confirmPassword: string;
};
export type TresetPassword = {
  newPassword: string;
  confirmPassword: string;
};
