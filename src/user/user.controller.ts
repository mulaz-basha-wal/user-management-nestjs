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
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ObjectId } from 'mongoose';
import { CreateUserDTO, UserSearchQueryDTO } from './dto/userDTOs';
import { MyLogger } from 'src/my-logger/my-logger.service';
import { AuthGuard } from 'src/auth/guards/auth.guard';
import { RoleGuard } from 'src/auth/guards/role.guard';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}
  private readonly logger = new MyLogger(UserController.name);

  @Post()
  async create(@Body() user: CreateUserDTO) {
    try {
      return await this.userService.create(user);
    } catch (error) {
      this.logger.error('Error creating user', error.stack);
      throw new HttpException('User creation failed', HttpStatus.BAD_REQUEST);
    }
  }

  @Get()
  @UseGuards(AuthGuard, RoleGuard)
  async findAll(@Query() query: UserSearchQueryDTO) {
    try {
      return await this.userService.findAll(query);
    } catch (error) {
      this.logger.error('Error fetching all users', error.stack);
      throw new HttpException(
        'Failed to fetch users',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  @Get('/:id')
  @UseGuards(AuthGuard, RoleGuard)
  async findOne(@Param('id') userId: ObjectId) {
    try {
      return await this.userService.findOne(userId);
    } catch (error) {
      this.logger.error(`Error fetching user with id ${userId}`, error.stack);
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }
  }

  @Patch('/:id')
  @UseGuards(AuthGuard, RoleGuard)
  async update(@Param('id') userId: ObjectId, @Body() updatedUser: any) {
    try {
      return await this.userService.update(userId, updatedUser);
    } catch (error) {
      this.logger.error(`Error updating user with id ${userId}`, error.stack);
      throw new HttpException('Failed to update user', HttpStatus.BAD_REQUEST);
    }
  }

  @Delete('/:id')
  @UseGuards(AuthGuard, RoleGuard)
  async delete(@Param('id') userId: ObjectId) {
    try {
      return await this.userService.delete(userId);
    } catch (error) {
      this.logger.error(`Error deleting user with id ${userId}`, error.stack);
      throw new HttpException('Failed to delete user', HttpStatus.BAD_REQUEST);
    }
  }
}
