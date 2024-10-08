import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { AUTH_PROVIDERS } from '../constants/auth.constants';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request: Request = context.switchToHttp().getRequest();
    const provider = request.cookies['provider'];
    const token = request.cookies['token'];
    const userId = request.cookies['userId'];
    const res = context.switchToHttp().getResponse();

    switch (provider) {
      case AUTH_PROVIDERS.GOOGLE:
        request.user = await this.authService.validateUserWithGoogle(
          token,
          userId,
          res,
        );
        return true;
      case AUTH_PROVIDERS.JWT:
        request.user = await this.authService.validateUserWithJWT(
          token,
          userId,
        );
        return true;
      case AUTH_PROVIDERS.LINKEDIN:
        request.user = await this.authService.validateUserWithLinkedin(
          token,
          userId,
          res,
        );
        return true;
    }
  }
}
