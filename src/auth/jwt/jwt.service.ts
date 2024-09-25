import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Token } from '../auth.constants';
import { Model } from 'mongoose';
import { randomUUID } from 'crypto';
import { InjectModel } from '@nestjs/mongoose';
import { AccessToken } from 'src/schemas/accessToken.schema';
import { RefreshToken } from 'src/schemas/refreshToken.schema';
import { USER_ROLES_BY_ID } from 'src/common/constants/user.constants';
import * as moment from 'moment';

@Injectable()
export class JwtAuthService {
  constructor(
    private jwtService: JwtService,
    @InjectModel(AccessToken.name) private accessToken: Model<AccessToken>,
    @InjectModel(RefreshToken.name) private refreshToken: Model<RefreshToken>,
  ) {}

  async create(payload: any, type: string, provider: string) {
    let expiresIn = process.env.JWT_ACCESS_TOKEN_EXPIRY;
    let secret = process.env.JWT_ACCESS_TOKEN_SECRET;
    const _n = { isRevoked: true, revokedAt: moment().toISOString() };

    if (type === Token.REFRESH) {
      expiresIn = process.env.JWT_REFRESH_TOKEN_EXPIRY;
      secret = process.env.JWT_REFRESH_TOKEN_SECRET;
    }

    payload.random = randomUUID();
    const token = this.jwtService.sign(payload, { expiresIn, secret });
    const decodedToken = this.jwtService.decode(token);
    const tokenInfo = {
      token,
      isRevoked: false,
      userId: payload._id,
      authProvider: provider,
      revokedAt: null,
      tokenExpiry: moment.unix(decodedToken.exp).toISOString(),
    };

    if (type === Token.ACCESS) {
      await this.accessToken.updateMany({ userId: payload._id }, _n);
      await this.accessToken.create(tokenInfo);
    } else {
      await this.refreshToken.updateMany({ userId: payload._id }, _n);
      await this.refreshToken.create(tokenInfo);
    }
    return token;
  }

  async read(token: string, type: string) {
    if (!token) return null;
    let info = null;
    const data = this.jwtService.decode(token);
    const cond = { token };

    if (type === Token.ACCESS) {
      info = await this.accessToken.findOne(cond).sort({ createdAt: -1 });
    } else {
      info = await this.refreshToken.findOne(cond).sort({ createdAt: -1 });
    }

    if (!info) return null;
    else {
      const token_data = {
        ...data,
        expires_at: data.exp,
        revokedAt: info.revokedAt,
        isRevoked: info.isRevoked,
        authProvider: info.authProvider,
        expiryAt: moment.unix(data.exp).toString(),
        userRole: USER_ROLES_BY_ID[data.userRoleId],
        fullName: `${data.firstName} ${data.lastName || ''}`,
        isAuthorized: moment.unix(data.exp).diff(moment()) > 0,
      };
      return token_data;
    }
  }

  async revoke(token: string, type: string) {
    const _token = await this.read(token, type);
    if (!_token) throw new UnauthorizedException('Invalid Token');

    const _c = { token, isRevoked: false };
    const _n = { isRevoked: true, revokedAt: moment().toISOString() };

    if (type === Token.ACCESS) await this.accessToken.updateOne(_c, _n);
    else await this.refreshToken.updateOne(_c, _n);
    return true;
  }

  async verify(token: string, type: string) {
    const tokenInfo = await this.read(token, type);
    if (!tokenInfo) throw new UnauthorizedException('Invalid token');

    return tokenInfo.isRevoked || !tokenInfo.isAuthorized;
  }
}
