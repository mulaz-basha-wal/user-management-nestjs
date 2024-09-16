import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  async getNewAccessToken(refreshToken: string): Promise<string> {
    try {
      //Todo: Call respective Oauth provide for new access token using refresh token
      return 'xyz_token_from_auth_provider' + refreshToken;
    } catch (error) {
      throw new Error('Failed to refresh the access token.');
    }
  }

  async getProfile(access_token: string) {
    try {
      //Todo: Call respective Oauth provide for profile with access_token
      return { profile: access_token };
    } catch (error) {
      console.error('Failed to revoke the token:', error);
    }
  }

  async isTokenExpired(token: string): Promise<boolean> {
    try {
      // Todo:
      // const response = await axios.get(
      //   `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${token}`,
      // );
      // const expiresIn = response.data.expires_in;
      return token === token;
    } catch (error) {
      return true;
    }
  }

  async revokeToken(access_token: string) {
    try {
      // await axios.get(
      //   `https://accounts.google.com/o/oauth2/revoke?token=${access_token}`,
      // );
      // Todo: check revoking options after each provider
      return access_token;
    } catch (error) {
      console.error('Failed to revoke the token:', error);
    }
  }
}
