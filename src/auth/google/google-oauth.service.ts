import axios from 'axios';
import { Injectable, Request, Res } from '@nestjs/common';
import {
  CookieOptions,
  epochStandard,
  OAUTH_PROVIDERS,
} from '../auth.constants';
import { UserService } from 'src/user/user.service';
import { CreateUserDTO } from 'src/user/dto/userDTOs';
import {
  USER_ROLES,
  USER_ROLES_BY_ID,
} from 'src/common/constants/user.constants';
import { errorHandler } from 'src/common/utils/apiErrorHandler';

@Injectable()
export class GoogleOauthService {
  private APIS_URL = 'https://www.googleapis.com/oauth2/v1';
  private ACCOUNTS_URL = 'https://accounts.google.com/o/oauth2';

  constructor(private userService: UserService) {}

  async googleLoginCallback(@Request() req, @Res() res) {
    const { firstName = '', lastName, email, picture } = req.user;
    const timestamp = new Date().toString();
    const userObj: CreateUserDTO = {
      email,
      lastName,
      firstName,
      isActive: true,
      password: 'default',
      profilePic: picture,
      userRoleId: USER_ROLES.USER,
      createdAt: timestamp,
      updatedAt: timestamp,
      roleLastUpdatedAt: timestamp,
      deletedAt: null,
    };

    res.cookie('access_token', req.user._accessToken, CookieOptions);
    res.cookie('refresh_token', req.user._refreshToken, CookieOptions);
    res.cookie('provider', OAUTH_PROVIDERS.GOOGLE, CookieOptions);

    await this.userService.create(userObj, false);
    res.redirect(process.env.CLIENT_AFTER_AUTH);
  }

  async getProfile(accessToken: string) {
    try {
      const res = await axios.get(`${this.APIS_URL}/userinfo`, {
        params: { alt: 'json', access_token: accessToken },
      });
      let userData = res.data;

      const response = await axios.get(`${this.APIS_URL}/tokeninfo`, {
        params: { alt: 'json', access_token: accessToken },
      });

      const user = await this.userService.findOneByMail(userData.email);
      userData = {
        ...userData,
        ...user.toObject(),
        isAuthorized: true,
        userRole: USER_ROLES_BY_ID[user.userRoleId],
      };
      const currentTime = new Date().getTime();
      const expires_at = epochStandard(
        response.data.expires_in * 1000 + (currentTime - 10),
      );
      userData.expires_at = expires_at;
      userData.currentTime = currentTime;
      return userData;
    } catch (error) {
      errorHandler(error, 'Failed to load user profile');
    }
  }

  async getNewAccessToken(refreshToken: string): Promise<string> {
    try {
      const response = await axios.post(`${this.ACCOUNTS_URL}/token`, {
        client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
        client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      });
      return response.data.access_token;
    } catch (error) {
      throw new Error('Failed to get the new access token.');
    }
  }

  async isTokenExpired(accessToken: string): Promise<boolean> {
    try {
      const response = await axios.get(`${this.APIS_URL}/tokeninfo`, {
        params: { alt: 'json', access_token: accessToken },
      });

      const expiresIn = response.data.expires_in;
      if (!expiresIn || expiresIn <= 0) {
        return true;
      }
    } catch (error) {
      return true;
    }
  }

  async revokeToken(accessToken: string) {
    try {
      await axios.get(`${this.ACCOUNTS_URL}/revoke?token=${accessToken}`);
    } catch (error) {
      throw new Error('Failed to revoke the token.');
    }
  }
}
