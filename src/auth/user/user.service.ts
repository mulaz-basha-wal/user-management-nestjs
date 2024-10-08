import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, ObjectId } from 'mongoose';
import {
  User,
  hashPasswordWithKey,
  verifyPasswordWithKey,
} from 'src/schemas/user.schema';
import {
  CreateUserDTO,
  UpdateUserDTO,
  UserSearchQueryDTO,
} from './dto/userDTOs';
import {
  ERROR_MESSAGES,
  USER_ROLES_BY_ID,
} from 'src/common/constants/user.constants';
import { errorHandler } from 'src/common/utils/apiErrorHandler';
import { LoginDTO } from 'src/auth/auth.constants';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(newUser: CreateUserDTO, isExit: boolean = true): Promise<User> {
    try {
      const userExist = await this.userModel.findOne({ email: newUser.email });
      if (userExist && !isExit) return userExist;
      if (userExist && isExit) {
        throw new ConflictException(ERROR_MESSAGES.USER_EXIST);
      }
      newUser.password = await hashPasswordWithKey(newUser.password);
      return await this.userModel.create(newUser);
    } catch (error) {
      if (error instanceof ConflictException) throw error;
      errorHandler(error, ERROR_MESSAGES.USER_CREATION_FAILED);
    }
  }

  async findAll(query: UserSearchQueryDTO): Promise<User[]> {
    try {
      query.page = query.page || 1;
      query.limit = query.limit || 5;

      let queryOptions = null;
      if (query.name) {
        const regexPattern = new RegExp(query.name, 'i');
        queryOptions = {
          $or: [
            { firstName: { $regex: regexPattern } },
            { lastName: { $regex: regexPattern } },
          ],
        };
      }

      const list = await this.userModel
        .find(queryOptions ?? {})
        .limit(query.limit)
        .skip((query.page - 1) * query.limit)
        .sort({ createdAt: -1 });
      return list.map((user: User) => {
        return {
          ...user.toObject(),
          userRole: USER_ROLES_BY_ID[user.userRoleId],
          fullName: `${user.firstName} ${user.lastName || ''}`,
        };
      });
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
    }
  }

  async countOfUsers(query: UserSearchQueryDTO): Promise<{ count: number }> {
    try {
      let queryOptions = null;
      if (query.name) {
        const regexPattern = new RegExp(query.name, 'i');
        queryOptions = {
          $or: [
            { firstName: { $regex: regexPattern } },
            { lastName: { $regex: regexPattern } },
          ],
        };
      }

      return { count: await this.userModel.countDocuments(queryOptions ?? {}) };
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
    }
  }

  async findOne(userId: ObjectId): Promise<User> {
    try {
      return await this.userModel.findOne({ _id: userId });
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
    }
  }

  async findOneByMail(email: string): Promise<User> {
    try {
      const user = await this.userModel.findOne({ email });
      return user;
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_FETCH_FAILED);
    }
  }

  async passwordCheck(credentials: LoginDTO): Promise<User | null> {
    try {
      const user = await this.userModel
        .findOne({ email: credentials.email })
        .select('+password');
      const validUser = await verifyPasswordWithKey(
        credentials.password,
        user.password,
      );
      user.password = undefined;
      if (validUser) return user;
      else return null;
    } catch (error) {
      return null;
    }
  }

  async update(userId: ObjectId, updatedUser: UpdateUserDTO): Promise<User> {
    try {
      const user = await this.userModel.findOne({ _id: userId });
      if (!user) throw new ConflictException(ERROR_MESSAGES.USER_NOT_EXIST);
      if (updatedUser.password) {
        updatedUser.password = await hashPasswordWithKey(updatedUser.password);
      }
      return await this.userModel.findOneAndUpdate(
        { _id: userId },
        updatedUser,
        { new: true },
      );
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_UPDATE_FAILED);
    }
  }

  async delete(userId: ObjectId): Promise<{ message: string }> {
    try {
      await this.userModel.findOneAndDelete({ _id: userId });
      return { message: ERROR_MESSAGES.USER_DELETED };
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_DELETE_FAILED);
    }
  }
}
