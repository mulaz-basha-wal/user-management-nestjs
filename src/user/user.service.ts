import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, ObjectId } from 'mongoose';
import { User } from 'src/schemas/user.schema';
import {
  CreateUserDTO,
  UpdateUserDTO,
  UserSearchQueryDTO,
} from './dto/userDTOs';
import { ERROR_MESSAGES } from 'src/common/constants/user.constants';
import { errorHandler } from 'src/common/utils/apiErrorHandler';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(newUser: CreateUserDTO): Promise<User> {
    try {
      if (newUser.password !== newUser.confirmPassword) {
        throw new BadRequestException(ERROR_MESSAGES.PASSWORDS_DO_NOT_MATCH);
      }

      const userExist = await this.userModel.findOne({ email: newUser.email });
      if (userExist) {
        throw new ConflictException(ERROR_MESSAGES.USER_EXIST);
      }

      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(newUser.password, saltRounds);

      const userToSave = {
        ...newUser,
        password: hashedPassword,
      };

      return await this.userModel.create(userToSave);
    } catch (error) {
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      errorHandler(error, ERROR_MESSAGES.USER_CREATION_FAILED);
    }
  }

  async findAll(
    query: UserSearchQueryDTO,
  ): Promise<{ users: User[]; count: number; page: number; limit: number }> {
    try {
      // Set default values for pagination
      query.page = query.page || 1;
      query.limit = query.limit || 5;

      let queryOptions = {};
      if (query.name) {
        const regexPattern = new RegExp(query.name, 'i');
        queryOptions = {
          $or: [
            { firstName: { $regex: regexPattern } },
            { lastName: { $regex: regexPattern } },
          ],
        };
      }

      const count = await this.userModel.countDocuments(queryOptions);

      const users = await this.userModel
        .find(queryOptions)
        .limit(query.limit)
        .skip((query.page - 1) * query.limit);

      return {
        users,
        count,
        page: query.page,
        limit: query.limit,
      };
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
      throw error;
    }
  }

  async findOne(userId: ObjectId): Promise<User> {
    try {
      return await this.userModel.findOne({ _id: userId });
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
    }
  }

  async update(userId: ObjectId, updatedUser: UpdateUserDTO): Promise<User> {
    try {
      const user = await this.userModel.findOne({ _id: userId });
      if (!user) throw new ConflictException(ERROR_MESSAGES.USER_NOT_EXIST);
      return await this.userModel.findOneAndUpdate(
        { _id: userId },
        updatedUser,
        { new: true },
      );
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_UPDATE_FAILED);
    }
  }

  async delete(userId: ObjectId): Promise<User> {
    try {
      return this.userModel.findOneAndDelete({ _id: userId });
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_DELETE_FAILED);
    }
  }
}
