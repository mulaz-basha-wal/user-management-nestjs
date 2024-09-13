import { Response } from 'express';
import { ConsentGuard, GoogleOauthGuard } from './google-oauth.guard';
import { Controller, Get, Req, Request, Res, UseGuards } from '@nestjs/common';
import { GoogleOauthService } from './google-oauth.service';

@Controller('auth/google')
export class GoogleOauthController {
  constructor(private googleOAuthService: GoogleOauthService) {}

  @Get()
  @UseGuards(ConsentGuard, GoogleOauthGuard)
  async googleLogin() {}

  @Get('callback')
  @UseGuards(GoogleOauthGuard)
  async googleAuthRedirect(@Request() req, @Res() res: Response) {
    this.googleOAuthService.googleLoginCallback(req, res);
  }

  @Get('logout')
  @UseGuards(GoogleOauthGuard)
  async logout(@Req() req, @Res() res: Response) {
    // const refreshToken = req.cookies['refresh_token'];
    // await this.authService.revokeGoogleToken(refreshToken);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.clearCookie('user_data');
    res.redirect(`${process.env.CLIENT_URL}/logged-out`);
  }
}
