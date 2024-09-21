import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt.strategy';
import { User } from 'src/schemas/user.schema';
import { CookieOptions, OAUTH_PROVIDERS } from '../auth.constants';
import { Response } from 'express';
import { USER_ROLES_BY_ID } from 'src/common/constants/user.constants';
import * as moment from 'moment';

@Injectable()
export class JwtAuthService {
  constructor(private jwtService: JwtService) {}

  verifyToken(token: string) {
    const user = this.jwtService.decode(token);
    if (!user || !user.exp) throw new UnauthorizedException('Invalid token');

    const tokenExpiry = user.exp;
    console.log('JwtAuthService ~ verifyToken ~ tokenExpiry:', tokenExpiry);
    const currentTime = moment().unix();
    console.log('JwtAuthService ~ verifyToken ~ currentTime:', currentTime);
    return tokenExpiry < currentTime;
  }

  getProfile(token: string) {
    const { user, exp } = this.jwtService.decode(token);
    const decoded = {
      ...user,
      expires_at: exp,
      isAuthorized: true,
      userRole: USER_ROLES_BY_ID[user.userRoleId],
      expiryAt: moment().toLocaleString(),
      fullName: `${user.firstName} ${user.lastName || ''}`,
    };
    return decoded;
  }

  signUpHandler(user: User, res: Response) {
    const payload: JwtPayload = { user };
    const accessToken = this.jwtService.sign(payload);

    res.cookie('access_token', accessToken, CookieOptions);
    res.cookie('refresh_token', null, CookieOptions);
    res.cookie('provider', OAUTH_PROVIDERS.JWT, CookieOptions);
    res.json(this.getProfile(accessToken));
  }

  signInHandler(user: User, res: Response) {
    const payload: JwtPayload = { user };
    const accessToken = this.jwtService.sign(payload);

    res.cookie('access_token', accessToken, CookieOptions);
    res.cookie('refresh_token', null, CookieOptions);
    res.cookie('provider', OAUTH_PROVIDERS.JWT, CookieOptions);
    res.json(this.getProfile(accessToken));
  }
}
