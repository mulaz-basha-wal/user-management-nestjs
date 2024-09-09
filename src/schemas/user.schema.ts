import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEmail } from 'class-validator';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true })
  @IsEmail()
  email: string;

  @Prop({ required: true, default: USER_ROLES.USER })
  userRoleId: USER_ROLES;

  @Prop()
  profilePic: string;

  @Prop({ required: true })
  createdAt: Date;

  @Prop({ required: true })
  updatedAt: Date;

  @Prop({ required: true })
  deletedAt: Date;

  @Prop({ required: true, default: false })
  isActive: boolean;

  @Prop({ required: true })
  roleLastUpdatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
