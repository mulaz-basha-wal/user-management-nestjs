import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Injectable()
export class RoleGuard extends AuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const canActivate = await super.canActivate(context);
    if (!canActivate) {
      return false;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (user.user && user.user.userRoleId === USER_ROLES.ADMIN) {
      return true;
    }

    throw new ForbiddenException('Access denied');
  }
}
