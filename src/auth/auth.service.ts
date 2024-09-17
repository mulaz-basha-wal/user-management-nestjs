import { Injectable } from '@nestjs/common';
import { GoogleOauthService } from './google/google-oauth.service';

@Injectable()
export class AuthService {
  constructor(private googleProvider: GoogleOauthService) {}

  async getNewAccessToken(
    refreshToken: string,
    provider: string,
  ): Promise<string> {
    switch (provider) {
      case 'google':
        return await this.googleProvider.getNewAccessToken(refreshToken);
      default:
        throw new Error('Invalid Auth provider');
    }
  }

  async getProfile(accessToken: string, provider: string) {
    switch (provider) {
      case 'google':
        return await this.googleProvider.getProfile(accessToken);
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
        case 'google':
          return await this.googleProvider.isTokenExpired(accessToken);
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
        case 'google':
          return await this.googleProvider.revokeToken(accessToken);
        default:
          throw new Error('Invalid Auth provider');
      }
    } catch (error) {
      return true;
    }
  }
}
