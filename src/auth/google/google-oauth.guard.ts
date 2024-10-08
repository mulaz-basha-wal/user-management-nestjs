import {
  Injectable,
  ExecutionContext,
  CanActivate,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AUTH_PROVIDERS, Token } from '../auth.constants';

@Injectable()
export class GoogleOauthGuard extends AuthGuard(AUTH_PROVIDERS.GOOGLE) {
  handleRequest(err, user, info, context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();

    if (req.query.error === 'access_denied') return null;
    if (err || !user) throw err || new UnauthorizedException();
    return user;
  }
}

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
