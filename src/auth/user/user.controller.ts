import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ObjectId } from 'mongoose';
import {
  CreateUserDTO,
  UpdateUserDTO,
  UserSearchQueryDTO,
} from './dto/userDTOs';
import { USER_ROLES } from 'src/common/constants/user.constants';
import { IsAuthenticated, RoleGuard } from 'src/auth/auth.guard';
import { Roles } from './role.decorator';
import { Token } from '../auth.constants';
import { Request } from 'express';
import { AuthService } from '../auth.service';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private authService: AuthService,
  ) {}

  @Post()
  create(@Body() user: CreateUserDTO) {
    user.userRoleId = USER_ROLES.USER;
    return this.userService.create(user);
  }

  @Get()
  @Roles(USER_ROLES.ADMIN)
  @UseGuards(RoleGuard, IsAuthenticated)
  findAll(@Query() query: UserSearchQueryDTO) {
    return this.userService.findAll(query);
  }

  @Get('/count')
  @Roles(USER_ROLES.ADMIN)
  @UseGuards(IsAuthenticated)
  count(@Query() query: UserSearchQueryDTO) {
    return this.userService.countOfUsers(query);
  }

  @Get('/:id')
  @Roles(USER_ROLES.ADMIN)
  @UseGuards(IsAuthenticated)
  findOne(@Param('id') userId: ObjectId) {
    return this.userService.findOne(userId);
  }

  @Patch('/:id')
  @Roles(USER_ROLES.USER, USER_ROLES.ADMIN)
  @UseGuards(IsAuthenticated)
  async update(
    @Param('id') userId: ObjectId,
    @Body() updatedUser: UpdateUserDTO,
    @Req() req: Request,
  ) {
    await this.userService.update(userId, updatedUser);
    return await this.authService.getProfile(
      req.cookies[Token.ACCESS],
      req.cookies[Token.PROVIDER],
    );
  }

  @Delete('/:id')
  @Roles(USER_ROLES.ADMIN)
  @UseGuards(RoleGuard, IsAuthenticated)
  delete(@Param('id') userId: ObjectId) {
    return this.userService.delete(userId);
  }
}
