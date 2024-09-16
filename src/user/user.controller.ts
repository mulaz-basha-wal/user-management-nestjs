import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
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
import { MyLogger } from 'src/my-logger/my-logger.service';
import { IsAuthenticated } from 'src/auth/auth.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  private readonly logger = new MyLogger(UserService.name);

  @Post()
  create(@Body() user: CreateUserDTO) {
    user.userRoleId = USER_ROLES.USER;
    return this.userService.create(user);
  }

  @Get()
  @UseGuards(IsAuthenticated)
  findAll(@Query() query: UserSearchQueryDTO) {
    this.logger.log(`Request for All users`, UserController.name);
    return this.userService.findAll(query);
  }

  @Get('/count')
  count(@Query() query: UserSearchQueryDTO) {
    return this.userService.countOfUsers(query);
  }

  @Get('/:id')
  findOne(@Param('id') userId: ObjectId) {
    return this.userService.findOne(userId);
  }

  @Patch('/:id')
  update(@Param('id') userId: ObjectId, @Body() updatedUser: UpdateUserDTO) {
    return this.userService.update(userId, updatedUser);
  }

  @Delete('/:id')
  delete(@Param('id') userId: ObjectId) {
    return this.userService.delete(userId);
  }
}
