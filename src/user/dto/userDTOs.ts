import { Date } from 'mongoose';
import { USER_ROLES } from 'src/common/constants/user.constants';

export class CreateUserDTO {
  name: string;
  email: string;
  userRoleId: USER_ROLES;
  profilePic: string;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date;
  isActive: boolean;
  roleLastUpdatedAt: Date;
}

export class UserSearchQueryDTO {
  page: number;
  limit: number;
}
