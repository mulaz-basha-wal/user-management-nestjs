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
import { CreateUserDTO } from './user/dto/userDTOs';
import { LoginDTO, ResetPassword, Token } from './auth.constants';
import { JwtAuthService } from './jwt/jwt.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private jwtAuthService: JwtAuthService,
  ) {}

  @Get('profile')
  @UseGuards(IsAuthenticated)
  async getProfile(@Request() req) {
    const provider = req.cookies[Token.PROVIDER];
    const accessToken = req.cookies[Token.ACCESS];
    return await this.authService.getProfile(accessToken, provider);
  }

  @Get('new_access')
  @UseGuards(IsAuthenticated)
  async getNewAccessToken(@Request() req) {
    const provider = req.cookies[Token.PROVIDER];
    const accessToken = req.cookies[Token.ACCESS];
    const refreshToken = req.cookies[Token.REFRESH];

    const profile = await this.authService.getProfile(accessToken, provider);
    if (profile && profile.isAuthorized) return profile;

    if (!refreshToken) throw new UnauthorizedException('No refresh token');
    const aToken = await this.authService.getNewAccessToken(
      refreshToken,
      provider,
    );
    return await this.jwtAuthService.read(aToken, Token.ACCESS);
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
    @Req() req,
    @Res() res: Response,
    @Body() auth: LoginDTO,
  ) {
    await this.authService.updatePasswordHandler(auth);
    await this.logout(req, res);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() user: { email: string }) {
    return await this.authService.forgotPasswordHandler(user.email);
  }

  @Post('reset-update')
  async resetPassword(@Body() password: string, @Query() query: ResetPassword) {
    return await this.authService.resetPasswordHandler(password, query.token);
  }

  @Get('logout')
  @UseGuards(IsAuthenticated)
  async logout(@Req() req, @Res() res: Response) {
    const refreshToken = req.cookies[Token.REFRESH];
    const accessToken = req.cookies[Token.ACCESS];
    const provider = req.cookies[Token.PROVIDER];
    const user = await this.authService.getProfile(accessToken, provider);

    await this.authService.revokeToken(accessToken, Token.ACCESS, provider);
    await this.authService.revokeToken(refreshToken, Token.REFRESH, provider);

    res.clearCookie(Token.ACCESS);
    res.clearCookie(Token.REFRESH);
    res.clearCookie(Token.PROVIDER);
    res.json({
      message: 'logout successful',
      code: 'LOGIN_AGAIN',
      user,
    });
  }
}
