import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { GoogleOauthService } from './google/google-oauth.service';
import { LoginDTO, AUTH_PROVIDERS, Token } from './auth.constants';
import { JwtAuthService } from './jwt/jwt.service';
import { CreateUserDTO } from 'src/auth/user/dto/userDTOs';
import { UserService } from 'src/auth/user/user.service';
import { Response } from 'express';
import { CredentialsService } from './credentials/credentials.service';
import { ERROR_MESSAGES } from 'src/common/constants/user.constants';

@Injectable()
export class AuthService {
  constructor(
    private googleProvider: GoogleOauthService,
    private jwtAuthService: JwtAuthService,
    private userService: UserService,
    private credService: CredentialsService,
  ) {}

  async signUpHandler(provider: string, data: CreateUserDTO, res: Response) {
    switch (provider) {
      case AUTH_PROVIDERS.CRED:
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
        if (user.isActive === false || user.deletedAt !== null) {
          throw new ForbiddenException();
        }
        if (user) return this.credService.signInHandler(user, res);
        else throw new UnauthorizedException('Invalid credentials');
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
}
