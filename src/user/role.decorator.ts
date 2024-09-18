import { SetMetadata } from '@nestjs/common';
import { USER_ROLES } from '../common/constants/user.constants';

export const ROLE_KEY = 'role';
export const Roles = (...role: USER_ROLES[]) => SetMetadata(ROLE_KEY, role);
