import { Injectable, ExecutionContext, CanActivate } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { OAUTH_PROVIDERS } from '../auth.constants';

@Injectable()
export class GoogleOauthGuard extends AuthGuard(OAUTH_PROVIDERS.GOOGLE) {}

@Injectable()
export class ConsentGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const accessToken = request.cookies['access_token'];

    if (accessToken) response.redirect(process.env.CLIENT_AFTER_AUTH);
    return true;
  }
}
