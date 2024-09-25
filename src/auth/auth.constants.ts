import { IsEmail, IsString } from 'class-validator';

export const CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: true,
};

export const AUTH_PROVIDERS = {
  GOOGLE: 'google',
  GITHUB: 'github',
  CRED: 'credential',
};

export class LoginDTO {
  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsString({ message: 'Invalid password' })
  password: string;
}

export const Token = {
  ACCESS: 'access_token',
  REFRESH: 'refresh_token',
  PROVIDER: 'provider',
};

export const TOKEN_REFRESH_HEADER = 'ums-token-refreshed';

export interface ResetPassword {
  token: string;
}
