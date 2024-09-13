import { Injectable, Request, Res } from '@nestjs/common';
import { CookieOptions } from '../auth.constants';
import { UserService } from 'src/user/user.service';
import { CreateUserDTO } from 'src/user/dto/userDTOs';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Injectable()
export class GoogleOauthService {
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
    res.cookie('user_data', userObj, CookieOptions);
    await this.userService.create(userObj, false);
    res.redirect(`${process.env.CLIENT_URL}/logged-in`);
  }
}
