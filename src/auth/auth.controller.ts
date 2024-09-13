import {
  Controller,
  Get,
  Request,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  @Get('profile')
  async getProfile(@Request() req) {
    const accessToken = req.cookies['access_token'];
    if (accessToken) {
      // return (await this.authService.getProfile(accessToken)).data;
      return {};
    }
    throw new UnauthorizedException('No access token');
  }

  @Get('logout')
  logout(@Req() req, @Res() res: Response) {
    // const refreshToken = req.cookies['refresh_token'];
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.clearCookie('user_data');
    // this.authService.revokeGoogleToken(refreshToken);
    res.redirect(`${process.env.CLIENT_URL}/logged-out`);
  }
}
