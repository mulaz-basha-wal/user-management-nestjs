import {
  Controller,
  Get,
  Request,
  Res,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { IsAuthenticated } from './auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get('profile')
  @UseGuards(IsAuthenticated)
  async getProfile(@Request() req) {
    const accessToken = req.cookies['access_token'];
    const provider = req.cookies['provider'];

    if (!accessToken) throw new UnauthorizedException('No access token');
    return await this.authService.getProfile(accessToken, provider);
  }

  @Get('logout')
  @UseGuards(IsAuthenticated)
  async logout(@Req() req, @Res() res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    const accessToken = req.cookies['access_token'];
    const provider = req.cookies['provider'];

    await this.authService.revokeToken(refreshToken, provider);
    await this.authService.revokeToken(accessToken, provider);

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    res.clearCookie('provider');
    res.json({
      message: 'logout successful',
      code: 'LOGIN_AGAIN',
    });
  }
}
