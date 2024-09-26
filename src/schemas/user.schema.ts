import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEmail } from 'class-validator';
import { USER_ROLES } from 'src/common/constants/user.constants';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true })
  firstName: string;

  @Prop({ required: true })
  lastName: string;

  @Prop({ required: true, unique: true })
  @IsEmail()
  email: string;

  @Prop({ default: null })
  password: string;

  @Prop({ required: true, default: USER_ROLES.USER })
  userRoleId: USER_ROLES;

  @Prop({ default: null })
  profilePic: string;

  @Prop({ default: null })
  deletedAt: Date;

  @Prop({ default: true })
  isVerified: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);
