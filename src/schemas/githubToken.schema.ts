import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class GithubToken extends Document {
  @Prop({ required: true, unique: true })
  token: string;

  @Prop({ required: true, ref: 'User' })
  userId: Types.ObjectId;

  @Prop({ required: true })
  isRevoked: boolean;
}

export const GithubTokenSchema = SchemaFactory.createForClass(GithubToken);
