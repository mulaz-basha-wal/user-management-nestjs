import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { CookieOptions } from './auth.constants';
import { AuthService } from './auth.service';
import { Reflector } from '@nestjs/core';
import { ROLE_KEY } from 'src/user/role.decorator';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Injectable()
export class IsAuthenticated implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const accessToken = request.cookies['access_token'];

    const provider = request.cookies['provider'];

    const isTokenExpired = await this.authService.isTokenExpired(
      accessToken,
      provider,
    );

    if (isTokenExpired) {
      const refreshToken = request.cookies['refresh_token'];
      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token not found');
      }

      try {
        const newAccessToken = await this.authService.getNewAccessToken(
          refreshToken,
          provider,
        );
        request.res.cookie('access_token', newAccessToken, CookieOptions);
        request.cookies['access_token'] = newAccessToken;
      } catch (error) {
        throw new UnauthorizedException('Failed to refresh token');
      }
    }
    return true;
  }
}

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<USER_ROLES[]>(
      ROLE_KEY,
      [context.getHandler(), context.getClass()],
    );

    const request = context.switchToHttp().getRequest();
    const profile = await this.authService.getProfile(
      request.cookies['access_token'],
      request.cookies['provider'],
    );

    if (requiredRoles.includes[profile && profile.userRoleId]) return true;
    return false;
  }
}
