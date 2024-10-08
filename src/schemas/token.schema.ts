import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';
import { AUTH_PROVIDERS } from 'src/auth/constants/auth.constants';

@Schema({ timestamps: true })
export class Token extends Document {
  @Prop({ required: true, type: mongoose.Schema.Types.ObjectId, ref: 'User' })
  userId: mongoose.Types.ObjectId;

  @Prop({ required: true, enum: AUTH_PROVIDERS })
  authProvider: string;

  @Prop({ required: false })
  accessToken: string;

  @Prop({ required: false })
  refreshToken: string;

  @Prop({ required: false })
  resetPasswordToken: string;

  @Prop({ required: false })
  resetPasswordExpiryDate: Date;
}

export const TokenSchema = SchemaFactory.createForClass(Token);
