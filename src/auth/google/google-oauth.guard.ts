import { Injectable, ExecutionContext, CanActivate } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AUTH_PROVIDERS, Token } from '../auth.constants';

@Injectable()
export class GoogleOauthGuard extends AuthGuard(AUTH_PROVIDERS.GOOGLE) {}

@Injectable()
export class GoogleConsentGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const accessToken = request.cookies[Token.ACCESS];

    if (accessToken) response.redirect(process.env.CLIENT_AFTER_AUTH);
    return true;
  }
}
