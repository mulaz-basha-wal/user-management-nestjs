import {
  Controller,
  Get,
  Request,
  Res,
  Req,
  UnauthorizedException,
  UseGuards,
  Post,
  Query,
  Body,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { IsAuthenticated } from './auth.guard';
import { CreateUserDTO } from 'src/user/dto/userDTOs';
import { LoginDTO } from './auth.constants';

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

  @Post('sign-up')
  async signUp(
    @Query() query: { provider: string },
    @Body() user: CreateUserDTO,
    @Res() res: Response,
  ) {
    return this.authService.signUpHandler(query.provider, user, res);
  }

  @Post('sign-in')
  async signIn(
    @Query() query: { provider: string },
    @Body() credentials: LoginDTO,
    @Res() res: Response,
  ) {
    return this.authService.signInHandler(query.provider, credentials, res);
  }

  @Post('password-update')
  @UseGuards(IsAuthenticated)
  async updatePassword(
    @Body() auth: LoginDTO,
    @Req() req,
    @Res() res: Response,
  ) {
    await this.authService.updatePasswordHandler(auth);
    await this.logout(req, res);
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
