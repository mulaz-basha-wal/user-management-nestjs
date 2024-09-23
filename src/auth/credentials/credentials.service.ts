import { Response } from 'express';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { User } from 'src/schemas/user.schema';
import { JwtAuthService } from '../jwt/jwt.service';
import { CookieOptions, AUTH_PROVIDERS, Token } from '../auth.constants';
import { RefreshToken } from 'src/schemas/refreshToken.schema';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';

@Injectable()
export class CredentialsService {
  constructor(
    private jwtService: JwtAuthService,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name) private refreshToken: Model<RefreshToken>,
  ) {}

  async signInHandler(payload: User, res: Response) {
    const user = payload.toObject();
    const aToken = await this.jwtService.create(
      user,
      Token.ACCESS,
      AUTH_PROVIDERS.CRED,
    );
    const rToken = await this.jwtService.create(
      user,
      Token.REFRESH,
      AUTH_PROVIDERS.CRED,
    );

    res.cookie(Token.ACCESS, aToken, CookieOptions);
    res.cookie(Token.REFRESH, rToken, CookieOptions);
    res.cookie(Token.PROVIDER, AUTH_PROVIDERS.CRED, CookieOptions);

    const tokenData = await this.jwtService.read(aToken, Token.ACCESS);
    res.json(tokenData);
  }

  async getNewAccessToken(token: string) {
    const rToken = (await this.refreshToken.findOne({ token })) as any;
    if (!rToken || rToken.isRevoked) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    } else {
      const user = await this.userModel.findOne({ _id: rToken.userId });
      return this.jwtService.create(
        user.toObject(),
        Token.ACCESS,
        AUTH_PROVIDERS.CRED,
      );
    }
  }

  async revokeToken(token: string, type: string) {
    await this.jwtService.revoke(token, type);
  }
}
