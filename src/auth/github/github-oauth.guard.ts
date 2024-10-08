import axios from 'axios';
import { AuthGuard } from '@nestjs/passport';
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDERS, CookieOptions, Token } from '../auth.constants';
import { Model, Types } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { JwtAuthService } from '../jwt/jwt.service';
import { User } from 'src/schemas/user.schema';
import { GithubToken } from 'src/schemas/githubToken.schema';

@Injectable()
export class GithubOAuthGuard extends AuthGuard(AUTH_PROVIDERS.GITHUB) {
  handleRequest(err, user, info, context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();

    if (req.query.error === 'access_denied') return null;

    if (err || !user) throw err || new UnauthorizedException();
    return user;
  }
}

@Injectable()
export class GithubConsentGuard implements CanActivate {
  constructor(
    private jwtAuthService: JwtAuthService,
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(GithubToken.name) private githubToken: Model<GithubToken>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const accessToken = request.cookies[Token.ACCESS];
    let status = false;
    let userId = null;

    try {
      if (accessToken) {
        const data = await this.jwtAuthService.read(accessToken, Token.ACCESS);
        if (!data) return true;

        userId = new Types.ObjectId(data._id);
        status = await this.isTokenRevoked(userId);
      } else {
        const query = request.query;
        if (!query.email) return true;
        const user = await this.userModel.findOne({ email: query.email });

        userId = user._id as Types.ObjectId;
        userId = new Types.ObjectId(userId);
        status = await this.isTokenRevoked(userId);
      }

      if (!status) {
        const user = await this.userModel.findOne({ _id: userId });
        const aToken = await this.jwtAuthService.create(
          user.toObject(),
          Token.ACCESS,
          AUTH_PROVIDERS.GITHUB,
        );
        const rToken = await this.jwtAuthService.create(
          user.toObject(),
          Token.REFRESH,
          AUTH_PROVIDERS.GITHUB,
        );

        response.cookie(Token.ACCESS, aToken, CookieOptions);
        response.cookie(Token.REFRESH, rToken, CookieOptions);
        response.cookie(Token.PROVIDER, AUTH_PROVIDERS.GITHUB, CookieOptions);

        response.redirect(process.env.CLIENT_AFTER_AUTH);
      }
      return status;
    } catch (error) {
      return true;
    }
  }

  async isTokenRevoked(userId: Types.ObjectId): Promise<boolean> {
    const gitToken = await this.githubToken
      .findOne({ userId, isRevoked: false })
      .sort({ createdAt: -1 });
    if (!gitToken) return true;

    try {
      await axios.get('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${gitToken.token}` },
      });
      return false;
    } catch (error) {
      if ([401, 403].includes(error?.response?.status)) {
        this.githubToken.updateOne(
          { token: gitToken.token },
          { isRevoked: true },
        );
        return true;
      }
      return false;
    }
  }
}
