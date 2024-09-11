import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
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

  @Prop({ required: true, select: false })
  password: string;

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

  comparePassword(password: string) {
    return bcrypt.compare(password, this.password);
  }

  generateAuthToken() {
    const token = jwt.sign(
      {
        _id: this._id,
        name: `${this.firstName} ${this.lastName}`,
        roleId: this.userRoleId,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRY || '1d',
      },
    );
    return token;
  }
}

export const UserSchema = SchemaFactory.createForClass(User);

UserSchema.pre('save', async function (next) {
  if (this.isNew || this.isModified('password')) {
    try {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(this.password, salt);
      this.password = hash;
      next();
    } catch (err) {
      return next(err);
    }
  } else {
    return next();
  }
});
