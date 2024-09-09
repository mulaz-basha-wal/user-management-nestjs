import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { IsEmail } from 'class-validator';
import { USER_ROLES } from 'src/common/constants/user.constants';

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  @IsEmail()
  email: string;

  @Prop({ required: true, default: USER_ROLES.USER })
  userRoleId: USER_ROLES;

  @Prop()
  profilePic: string;

  @Prop({ default: null })
  deletedAt: Date;

  @Prop({ required: true, default: true })
  isActive: boolean;

  @Prop({ default: () => new Date() })
  roleLastUpdatedAt: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
