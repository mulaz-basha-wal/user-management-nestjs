import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { CookieOptions, Token, TOKEN_REFRESH_HEADER } from './auth.constants';
import { AuthService } from './auth.service';
import { Reflector } from '@nestjs/core';
import { ROLE_KEY } from 'src/auth/user/role.decorator';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Injectable()
export class IsAuthenticated implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const accessToken = request.cookies[Token.ACCESS];
    const provider = request.cookies[Token.PROVIDER];

    let isTokenExpired = true;
    if (accessToken) {
      isTokenExpired = await this.authService.isTokenExpired(
        accessToken,
        provider,
      );
    }

    if (isTokenExpired) {
      const refreshToken = request.cookies[Token.REFRESH];
      if (!refreshToken) throw new UnauthorizedException();

      try {
        const newAccessToken = await this.authService.getNewAccessToken(
          refreshToken,
          provider,
        );
        request.cookies[Token.ACCESS] = newAccessToken;
        request.res.cookie(Token.ACCESS, newAccessToken, CookieOptions);
        request.res.set(TOKEN_REFRESH_HEADER, true);
        return true;
      } catch (error) {
        throw new UnauthorizedException();
      }
    } else {
      request.res.set(TOKEN_REFRESH_HEADER, false);
      return true;
    }
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
      request.cookies[Token.ACCESS],
      request.cookies[Token.PROVIDER],
    );

    if (requiredRoles.some((role) => role === profile.userRoleId)) return true;
    return false;
  }
}
