import { Response } from 'express';
import { ConsentGuard, GoogleOauthGuard } from './google-oauth.guard';
import { Controller, Get, Request, Res, UseGuards } from '@nestjs/common';
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
}
