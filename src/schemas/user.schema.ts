import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEmail } from 'class-validator';
import { USER_ROLES } from 'src/common/constants/user.constants';
import { Document } from 'mongoose';
import * as argon2 from 'argon2';

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  firstName: string;

  @Prop({ required: false, default: null })
  lastName: string;

  @Prop({ required: true, unique: true })
  @IsEmail()
  email: string;

  @Prop({ required: true, select: false })
  password: string;

  @Prop({ required: true, default: USER_ROLES.USER })
  userRoleId: USER_ROLES;

  @Prop()
  profilePic: string;

  @Prop({ default: null })
  deletedAt: Date;

  @Prop({ required: true, default: false })
  isActive: boolean;

  @Prop({ default: () => new Date() })
  roleLastUpdatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);

export const hashPasswordWithKey = async (password: string) => {
  const combinedPassword = password + process.env.PASSWORD_HASH_CHUNK;
  const hash = await argon2.hash(combinedPassword);
  return hash;
};

export const verifyPasswordWithKey = async (password: string, hash: string) => {
  const combinedPassword = password + process.env.PASSWORD_HASH_CHUNK;
  const isSame = await argon2.verify(hash, combinedPassword);
  return isSame;
};

UserSchema.set('toJSON', {
  transform: function (doc, record) {
    delete record.password;
    return record;
  },
});
