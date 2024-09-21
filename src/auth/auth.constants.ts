import { IsEmail, IsString } from 'class-validator';

export const CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: true,
};

export const OAUTH_PROVIDERS = {
  GOOGLE: 'google',
  JWT: 'jwt',
};

export class LoginDTO {
  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsString({ message: 'Invalid password' })
  password: string;
}
