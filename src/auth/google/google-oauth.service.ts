import axios from 'axios';
import { Injectable, Request, Res } from '@nestjs/common';
import { CookieOptions, AUTH_PROVIDERS, Token } from '../auth.constants';
import { UserService } from 'src/auth/user/user.service';
import { CreateUserDTO } from 'src/auth/user/dto/userDTOs';
import {
  USER_ROLES,
  USER_ROLES_BY_ID,
} from 'src/common/constants/user.constants';
import { errorHandler } from 'src/common/utils/apiErrorHandler';
import * as moment from 'moment';

@Injectable()
export class GoogleOauthService {
  private APIS_URL = 'https://www.googleapis.com/oauth2/v1';
  private ACCOUNTS_URL = 'https://accounts.google.com/o/oauth2';

  constructor(private userService: UserService) {}

  async googleLoginCallback(@Request() req, @Res() res) {
    const { firstName = '', lastName, email, picture } = req.user;
    const timestamp = moment().toString();
    const userObj: CreateUserDTO = {
      email,
      lastName,
      firstName,
      isActive: true,
      isPasswordSet: false,
      password: null,
      profilePic: picture,
      userRoleId: USER_ROLES.USER,
      createdAt: timestamp,
      updatedAt: timestamp,
      roleLastUpdatedAt: timestamp,
      deletedAt: null,
    };

    res.cookie(Token.ACCESS, req.user._accessToken, CookieOptions);
    res.cookie(Token.REFRESH, req.user._refreshToken, CookieOptions);
    res.cookie(Token.PROVIDER, AUTH_PROVIDERS.GOOGLE, CookieOptions);

    await this.userService.create(userObj, false);
    res.redirect(process.env.CLIENT_AFTER_AUTH);
  }

  async getProfile(accessToken: string) {
    try {
      const res = await axios.get(`${this.APIS_URL}/userinfo`, {
        params: { alt: 'json', access_token: accessToken },
      });
      const response = await axios.get(`${this.APIS_URL}/tokeninfo`, {
        params: { alt: 'json', access_token: accessToken },
      });

      const user = await this.userService.findOneByMail(res.data.email);
      const expires_at = moment()
        .add(response.data.expires_in - 5, 'seconds')
        .unix();

      const profile = {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        userRoleId: user.userRoleId,
        isActive: user.isActive,
        roleLastUpdatedAt: user.roleLastUpdatedAt,
        createdAt: user['createdAt'],
        updatedAt: user['updatedAt'],
        deletedAt: user.deletedAt,
        exp: expires_at,
        expires_at,
        revokedAt: null,
        isRevoked: false,
        authProvider: AUTH_PROVIDERS.GOOGLE,
        expiryAt: moment.unix(expires_at).toString(),
        userRole: USER_ROLES_BY_ID[user.userRoleId],
        fullName: `${user.firstName} ${user.lastName || ''}`,
        isAuthorized: response.data.expires_in > 0,
      };
      return profile;
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
