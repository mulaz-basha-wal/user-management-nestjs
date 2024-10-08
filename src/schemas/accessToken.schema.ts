import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class AccessToken extends Document {
  @Prop({ required: true, unique: true })
  token: string;

  @Prop({ required: true, ref: 'User' })
  userId: Types.ObjectId;

  @Prop({ required: true })
  isRevoked: boolean;

  @Prop({ required: true })
  authProvider: string;

  @Prop({ default: null })
  revokedAt: Date;

  @Prop({ required: true })
  tokenExpiry: Date;
}

export const AccessTokenSchema = SchemaFactory.createForClass(AccessToken);
