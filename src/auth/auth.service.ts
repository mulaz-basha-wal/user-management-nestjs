import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
  NotFoundException,
  RequestTimeoutException,
} from '@nestjs/common';
import { GoogleOauthService } from './google/google-oauth.service';
import { LoginDTO, AUTH_PROVIDERS, Token } from './auth.constants';
import { JwtAuthService } from './jwt/jwt.service';
import { CreateUserDTO } from 'src/auth/user/dto/userDTOs';
import { UserService } from 'src/auth/user/user.service';
import { Response } from 'express';
import { CredentialsService } from './credentials/credentials.service';
import { ERROR_MESSAGES } from 'src/common/constants/user.constants';
import { maskEmail } from 'src/common/utils';
import { MailService } from 'src/mail/mail.service';
import * as jwt from 'jsonwebtoken';
import * as moment from 'moment';

@Injectable()
export class AuthService {
  constructor(
    private googleProvider: GoogleOauthService,
    private jwtAuthService: JwtAuthService,
    private userService: UserService,
    private credService: CredentialsService,
    private mailService: MailService,
  ) {}

  async signUpHandler(provider: string, data: CreateUserDTO, res: Response) {
    switch (provider) {
      case AUTH_PROVIDERS.CRED:
        data.isPasswordSet = true;
        const user = await this.userService.create(data);
        if (user) return this.credService.signInHandler(user, res);
        else throw new ConflictException(ERROR_MESSAGES.USER_CREATION_FAILED);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async signInHandler(provider: string, data: LoginDTO, res: Response) {
    switch (provider) {
      case AUTH_PROVIDERS.CRED:
        const user = await this.userService.passwordCheck(data);
        if (!user) throw new UnauthorizedException('Invalid credentials');
        if (user.isActive === false || user.deletedAt !== null) {
          throw new ForbiddenException('User blocked/deleted');
        }
        return this.credService.signInHandler(user, res);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async getNewAccessToken(
    refreshToken: string,
    provider: string,
  ): Promise<string> {
    switch (provider) {
      case AUTH_PROVIDERS.GOOGLE:
        return await this.googleProvider.getNewAccessToken(refreshToken);
      case AUTH_PROVIDERS.CRED:
      case AUTH_PROVIDERS.GITHUB:
        return await this.credService.getNewAccessToken(refreshToken);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async getProfile(accessToken: string, provider: string) {
    switch (provider) {
      case AUTH_PROVIDERS.GOOGLE:
        return await this.googleProvider.getProfile(accessToken);
      case AUTH_PROVIDERS.CRED:
      case AUTH_PROVIDERS.GITHUB:
        const auth = await this.jwtAuthService.read(accessToken, Token.ACCESS);
        auth.provider = provider;
        return auth;
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async isTokenExpired(
    accessToken: string,
    provider: string,
  ): Promise<boolean> {
    try {
      switch (provider) {
        case AUTH_PROVIDERS.GOOGLE:
          return await this.googleProvider.isTokenExpired(accessToken);
        case AUTH_PROVIDERS.CRED:
        case AUTH_PROVIDERS.GITHUB:
          return await this.jwtAuthService.verify(accessToken, Token.ACCESS);
        default:
          throw new Error('Invalid Auth provider');
      }
    } catch (error) {
      return true;
    }
  }

  async revokeToken(token: string, type: string, provider: string) {
    try {
      switch (provider) {
        case AUTH_PROVIDERS.GOOGLE:
          return await this.googleProvider.revokeToken(token);
        case AUTH_PROVIDERS.CRED:
        case AUTH_PROVIDERS.GITHUB:
          return this.credService.revokeToken(token, type);
        default:
          throw new Error('Invalid Auth provider');
      }
    } catch (error) {
      return true;
    }
  }

  async updatePasswordHandler(data: LoginDTO) {
    try {
      const user = await this.userService.findOneByMail(data.email);
      const userId = await user.toObject()._id;
      const newU = await this.userService.update(userId, data);
      return newU;
    } catch (error) {
      throw new Error('Failed to update the password');
    }
  }

  async forgotPasswordHandler(email: string) {
    if (!email) throw new ForbiddenException('Invalid User');
    const user = await this.userService.findOneByMail(email);
    if (user) {
      const token = jwt.sign(
        { id: user._id },
        process.env.JWT_ACCESS_TOKEN_SECRET,
        { expiresIn: '30m' },
      );
      const resetLink = `${process.env.CLIENT_URL}/reset_password?token=${token}`;

      await this.mailService.sendMail(
        email,
        `[IMP] Reset password - ${process.env.APP_NAME}`,
        'forgot-password',
        {
          resetLink,
          userName: user.firstName,
          appName: process.env.APP_NAME,
        },
      );
      return {
        message: `We have e-mailed your password reset link at ${maskEmail(email)}`,
      };
    } else {
      throw new NotFoundException('Invalid User');
    }
  }

  async resetPasswordHandler(password: string, token: string) {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET);
    if (!decoded || moment().unix() >= decoded.exp) {
      throw new RequestTimeoutException(
        'Invalid/Expired link, please re-try changing password',
      );
    }

    const user = await this.userService.findOne(decoded.id);
    if (!user) throw new NotFoundException('Invalid User');

    await this.userService.update(decoded.id, {
      password,
      isPasswordSet: true,
    });
    return {
      message: 'Password reset successfully, please try sign-in.',
    };
  }
}
