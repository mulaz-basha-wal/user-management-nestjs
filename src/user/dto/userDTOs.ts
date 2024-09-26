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
import { Date } from 'mongoose';
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

  confirmPassword: string;

  @IsOptional()
  @IsEnum(USER_ROLES, { message: 'Invalid user role' })
  userRoleId: USER_ROLES;

  @IsOptional()
  @IsString()
  profilePic: string;

  @IsOptional()
  @IsDate()
  @Type(() => Date)
  createdAt: Date;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  updatedAt: Date;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  deletedAt: Date;

  @IsBoolean()
  @IsOptional()
  isVerified: boolean;

  @IsDate()
  @Type(() => Date)
  @IsOptional()
  roleLastUpdatedAt: Date;
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

export class UpdateUserDTO extends PartialType(CreateUserDTO) {
  @IsOptional()
  userRoleId: number;
}
