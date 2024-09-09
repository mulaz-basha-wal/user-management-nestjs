import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, ObjectId } from 'mongoose';
import { User } from 'src/schemas/user.schema';
import { CreateUserDTO, UserSearchQueryDTO } from './dto/userDTOs';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async create(createUserDto: CreateUserDTO): Promise<User> {
    const createdUser = new this.userModel(createUserDto);
    return createdUser.save();
  }

  async findAll(query: UserSearchQueryDTO): Promise<User[]> {
    const _query = this.userModel.find();
    if (query.page && query.limit) {
      const skipPages = query.page - 1;
      _query.limit(query.limit).skip(skipPages * query.limit);
    }
    return _query.sort({ age: 1 }).exec();
  }

  async findOne(userId: ObjectId): Promise<User> {
    return await this.userModel.findOne({ _id: userId });
  }

  async update(userId: ObjectId, updatedUser: CreateUserDTO): Promise<User> {
    return await this.userModel.findOneAndUpdate({ _id: userId }, updatedUser, {
      new: true,
    });
  }

  async delete(userId: ObjectId): Promise<User[]> {
    return this.userModel.findOneAndDelete({ _id: userId });
  }
}
