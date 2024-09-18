import { Injectable, UnauthorizedException } from '@nestjs/common';
import { GoogleOauthService } from './google/google-oauth.service';
import { LoginDTO, OAUTH_PROVIDERS } from './auth.constants';
import { JwtAuthService } from './jwt/jwt.service';
import { CreateUserDTO } from 'src/user/dto/userDTOs';
import { UserService } from 'src/user/user.service';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private googleProvider: GoogleOauthService,
    private jwtAuthService: JwtAuthService,
    private userService: UserService,
  ) {}

  async signUpHandler(provider: string, data: CreateUserDTO, res: Response) {
    switch (provider) {
      case OAUTH_PROVIDERS.JWT:
        const user = await this.userService.create(data);
        return this.jwtAuthService.signUpHandler(user, res);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async signInHandler(provider: string, data: LoginDTO, res: Response) {
    switch (provider) {
      case OAUTH_PROVIDERS.JWT:
        const user = await this.userService.passwordCheck(data);
        if (user) {
          return this.jwtAuthService.signInHandler(user, res);
        } else throw new UnauthorizedException('Invalid credentials');
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async getNewAccessToken(
    refreshToken: string,
    provider: string,
  ): Promise<string> {
    switch (provider) {
      case OAUTH_PROVIDERS.GOOGLE:
        return await this.googleProvider.getNewAccessToken(refreshToken);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async getProfile(accessToken: string, provider: string) {
    switch (provider) {
      case OAUTH_PROVIDERS.GOOGLE:
        return await this.googleProvider.getProfile(accessToken);
      case OAUTH_PROVIDERS.JWT:
        return await this.jwtAuthService.getProfile(accessToken);
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
        case OAUTH_PROVIDERS.GOOGLE:
          return await this.googleProvider.isTokenExpired(accessToken);
        case OAUTH_PROVIDERS.JWT:
          return this.jwtAuthService.verifyToken(accessToken);
        default:
          throw new Error('Invalid Auth provider');
      }
    } catch (error) {
      return true;
    }
  }

  async revokeToken(accessToken: string, provider: string) {
    try {
      switch (provider) {
        case OAUTH_PROVIDERS.GOOGLE:
          return await this.googleProvider.revokeToken(accessToken);
        case OAUTH_PROVIDERS.JWT:
          return null;
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
