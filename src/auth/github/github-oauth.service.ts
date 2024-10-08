import { Model, Types } from 'mongoose';
import * as moment from 'moment';
import { InjectModel } from '@nestjs/mongoose';
import { Injectable, Request, Res } from '@nestjs/common';
import { UserService } from 'src/auth/user/user.service';
import { CreateUserDTO } from '../user/dto/userDTOs';
import { USER_ROLES } from 'src/common/constants/user.constants';
import { AUTH_PROVIDERS, CookieOptions, Token } from '../auth.constants';
import { JwtAuthService } from '../jwt/jwt.service';
import { GithubToken } from 'src/schemas/githubToken.schema';
import { authorizationErrorLink } from 'src/common/utils';

@Injectable()
export class GithubOAuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtAuthService,
    @InjectModel(GithubToken.name) private githubToken: Model<GithubToken>,
  ) {}

  async loginCallback(@Request() req, @Res() res) {
    if (!req.user || req.query.error) {
      return res.redirect(authorizationErrorLink(req, AUTH_PROVIDERS.GITHUB));
    }
    const { firstName, lastName, email, picture } = req.user;
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

    const user = await this.userService.create(userObj, false);
    let userId = user._id as Types.ObjectId;
    userId = new Types.ObjectId(userId);

    await this.githubToken.updateMany(
      { userId, isRevoked: false },
      { isRevoked: true },
    );
    await this.githubToken.create({
      token: req.user.accessToken,
      userId: user._id,
      isRevoked: false,
    });

    user.password = undefined;
    const aToken = await this.jwtService.create(
      user.toObject(),
      Token.ACCESS,
      AUTH_PROVIDERS.GITHUB,
    );
    const rToken = await this.jwtService.create(
      user.toObject(),
      Token.REFRESH,
      AUTH_PROVIDERS.GITHUB,
    );

    res.cookie(Token.ACCESS, aToken, CookieOptions);
    res.cookie(Token.REFRESH, rToken, CookieOptions);
    res.cookie(Token.PROVIDER, AUTH_PROVIDERS.GITHUB, CookieOptions);

    res.redirect(process.env.CLIENT_AFTER_AUTH);
  }
}
