import { PartialType } from '@nestjs/mapped-types';
import { Type } from 'class-transformer';
import {
  IsBoolean,
  IsDate,
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';
import { USER_ROLES } from 'src/common/constants/user.constants';

export class CreateUserDTO {
  @IsString()
  @IsOptional()
  firstName: string;

  @IsString()
  @IsOptional()
  lastName: string;

  @IsEmail({}, { message: 'Invalid email address' })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(20, { message: 'Password cannot exceed 20 characters' })
  @Matches(/(?=.*[A-Z])/, {
    message: 'Password must contain at least one uppercase letter.',
  })
  @Matches(/(?=.*[a-z])/, {
    message: 'Password must contain at least one lowercase letter.',
  })
  @Matches(/(?=.*\d)/, {
    message: 'Password must contain at least one number.',
  })
  @Matches(/(?=.*\W)/, {
    message: 'Password must contain at least one special character.',
  })
  password: string;

  @IsOptional()
  @IsEnum(USER_ROLES, { message: 'Invalid user role' })
  userRoleId: USER_ROLES;

  @IsOptional()
  @IsString()
  profilePic: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  createdAt: string;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  updatedAt: string;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  deletedAt: string;

  @IsBoolean()
  @IsOptional()
  isActive: boolean;

  @IsBoolean()
  @IsOptional()
  isPasswordSet: boolean;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  roleLastUpdatedAt: string;
}

export class UserSearchQueryDTO {
  @Type(() => Number)
  @IsOptional()
  page: number;

  @Type(() => Number)
  @IsOptional()
  limit: number;

  @IsString()
  @IsOptional()
  name: string;

  @IsEmail()
  @IsOptional()
  email: string;
}

export class UpdateUserDTO extends PartialType(CreateUserDTO) {}

export interface UserAuthData {
  _id: string;
  firstName: string;
  lastName: string;
  email: string;
  userRoleId: number;
  deletedAt: string | null;
  isActive: boolean;
  roleLastUpdatedAt: string;
  createdAt: string;
  updatedAt: string;
  exp: number;
  expires_at: number;
  revokedAt: string | null;
  isRevoked: boolean;
  authProvider: string;
  expiryAt: string;
  userRole: string;
  fullName: string;
  isAuthorized: boolean;
}
