import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { CookieOptions } from './auth.constants';
import { AuthService } from './auth.service';

@Injectable()
export class IsAuthenticated implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const accessToken = request.cookies['access_token'];
    const isTokenExpired = await this.authService.isTokenExpired(accessToken);

    if (isTokenExpired) {
      const refreshToken = request.cookies['refresh_token'];
      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token not found');
      }

      try {
        const newAccessToken =
          await this.authService.getNewAccessToken(refreshToken);
        request.res.cookie('access_token', newAccessToken, CookieOptions);
        request.cookies['access_token'] = newAccessToken;
      } catch (error) {
        throw new UnauthorizedException('Failed to refresh token');
      }
    }
    return true;
  }
}
