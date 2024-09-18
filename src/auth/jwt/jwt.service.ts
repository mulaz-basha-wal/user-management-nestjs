import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './jwt.strategy';
import { User } from 'src/schemas/user.schema';
import {
  CookieOptions,
  epochStandard,
  OAUTH_PROVIDERS,
} from '../auth.constants';
import { Response } from 'express';
import { USER_ROLES_BY_ID } from 'src/common/constants/user.constants';

@Injectable()
export class JwtAuthService {
  constructor(private jwtService: JwtService) {}

  verifyToken(token: string) {
    const decoded = this.jwtService.decode(token);
    if (!decoded || !decoded.exp) {
      throw new UnauthorizedException('Invalid token');
    }
    return epochStandard(decoded.exp) < epochStandard(new Date().getTime());
  }

  getProfile(token: string) {
    let decoded = this.jwtService.decode(token);
    decoded = {
      ...decoded.user,
      isAuthorized: true,
      expires_at: epochStandard(decoded.exp),
      expires_data: new Date(decoded.exp).toLocaleString(),
      userRole: USER_ROLES_BY_ID[decoded.user.userRoleId],
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
