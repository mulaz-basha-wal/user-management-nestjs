import {
  Body,
  Controller,
  Get,
  Patch,
  Post,
  Req,
  Res,
  UseGuards,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { GoogleAuthGuard } from './guards/google.guard';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { AUTH_PROVIDERS } from './constants/auth.constants';
import { AuthGuard } from './guards/auth.guard';
import { LoginUser } from './interfaces/auth.interface';
import { MyLogger } from 'src/my-logger/my-logger.service';
import { errorHandler } from 'src/common/utils/apiErrorHandler';
import { UpdateUserDTO } from 'src/user/dto/userDTOs';
import { LinkedinAuthGuard } from './guards/linkedin.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  private readonly logger = new MyLogger(AuthController.name);

  @Post('/login')
  async loginUser(@Body() user: LoginUser, @Res() res: Response) {
    try {
      const loggedUser = await this.authService.loginUser(user, res);
      return res.json({
        success: true,
        user: { _id: loggedUser._id, email: loggedUser.email },
      });
    } catch (error) {
      this.logger.error('Login failed', error.stack);
      errorHandler(error, 'Login failed', HttpStatus.UNAUTHORIZED);
    }
  }

  @Get('/google/login')
  @UseGuards(GoogleAuthGuard)
  handleLogin() {}

  @Get('/google/redirect')
  @UseGuards(GoogleAuthGuard)
  async handleRedirection(@Req() req, @Res() res: Response) {
    try {
      await this.authService.signInWithGoogle(req.user, res);
      return res.redirect(process.env.GOOGLE_REDIRECT_URL_CLIENT);
    } catch (error) {
      this.logger.error('Google login redirection failed', error.stack);
      errorHandler(
        error,
        'Google login redirection failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('/linkedin/login')
  loginWithLinkedin(@Res() res: Response) {
    const linkedinAuthUrl = 'https://www.linkedin.com/oauth/v2/authorization';
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.LINKEDIN_CLIENT_ID,
      redirect_uri: `${process.env.BASE_URL}${process.env.LINKEDIN_REDIRECT_URL}`,
      scope: 'openid profile email w_member_social',
    });

    res.redirect(`${linkedinAuthUrl}?${params.toString()}`);
  }

  @Get('/linkedin/redirect')
  @UseGuards(LinkedinAuthGuard)
  async handleLinkedinRedirection(@Req() req, @Res() res: Response) {
    try {
      await this.authService.signInWithLinkedin(req.user, res);
      return res.redirect(process.env.LINKEDIN_REDIRECT_URL_CLIENT);
    } catch (error) {
      this.logger.error('Linkedin login redirection failed', error.stack);
      errorHandler(
        error,
        'Linkedin login redirection failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('/logout')
  async user(@Req() request: Request, @Res() res: Response) {
    try {
      switch (request.cookies['provider']) {
        case AUTH_PROVIDERS.GOOGLE:
          await this.authService.revokeGoogleToken(request.cookies['token']);
          break;
        case AUTH_PROVIDERS.LINKEDIN:
          await this.authService.revokeLinkedinToken(request.cookies['token']);
          break;
        default:
          break;
      }
      res.clearCookie('token');
      res.clearCookie('provider');
      res.clearCookie('userId');
      return res.json({ msg: 'success logout' });
    } catch (error) {
      this.logger.error('Logout failed', error.stack);
      errorHandler(error, 'Logout failed', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/loggedInUser')
  @UseGuards(AuthGuard)
  async loggedUser(@Req() req: Request, @Res() res: Response) {
    const user = req.user as any;
    const providersList = await this.authService.getUserProvidersList(
      user.user.id,
    );
    return res.json({ user: user.user, providers: providersList });
  }

  @Patch('/change-password')
  @UseGuards(AuthGuard)
  async changePassword(
    @Req() req: Request,
    @Body()
    body: {
      oldPassword: string;
      newPassword: string;
      confirmNewPassword: string;
    },
  ) {
    try {
      await this.authService.updatePassword(req, body);
      return { message: 'Password updated successfully' };
    } catch (error) {
      this.logger.error('Password update failed', error.stack);
      errorHandler(error, 'Password update failed', HttpStatus.BAD_REQUEST);
    }
  }

  @Post('/forgot-password')
  async forgotPassword(@Body() { email }) {
    try {
      await this.authService.forgotPassword(email);
      return { message: 'Reset password link sent to registered mail' };
    } catch (error) {
      this.logger.error('Failed to send reset password link', error.stack);
      errorHandler(
        error,
        'Failed to send reset password link',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('/reset-password/verify')
  async verifyResetPasswordLink(
    @Body()
    { token, userId }: { token: string; userId: string },
  ) {
    try {
      await this.authService.verifyResetPasswordLink(token, userId);
      return { success: true };
    } catch (error) {
      this.logger.error('reset Password Link expired', error.stack);
      return errorHandler(
        error,
        'reset Password Link expired',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Post('/reset-password')
  async resetPassword(
    @Body()
    {
      token,
      userId,
      newPassword,
      confirmPassword,
    }: {
      token: string;
      userId: string;
      newPassword: string;
      confirmPassword: string;
    },
  ) {
    try {
      const result = await this.authService.resetPassword(
        token,
        userId,
        newPassword,
        confirmPassword,
      );
      return { message: result.message };
    } catch (error) {
      this.logger.error('Error resetting password', error.stack);
      return errorHandler(
        error,
        'Password reset failed',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Patch('/update-profile')
  @UseGuards(AuthGuard)
  async update(@Body() updatedUser: UpdateUserDTO, @Req() req: Request) {
    const user = req.user as any;
    try {
      return await this.authService.updateProfile(user.user.email, updatedUser);
    } catch (error) {
      this.logger.error(
        `Error updating user with email ${user.email}`,
        error.stack,
      );
      throw new HttpException('Failed to update user', HttpStatus.BAD_REQUEST);
    }
  }
}
