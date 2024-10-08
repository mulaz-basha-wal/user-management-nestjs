import { Module } from '@nestjs/common';
import { CredentialsService } from './credentials.service';
import { JwtAuthModule } from '../jwt/jwt.module';
import { MongooseModule } from '@nestjs/mongoose';
import { AccessToken, AccessTokenSchema } from 'src/schemas/accessToken.schema';
import {
  RefreshToken,
  RefreshTokenSchema,
} from 'src/schemas/refreshToken.schema';
import { User, UserSchema } from 'src/schemas/user.schema';

@Module({
  imports: [
    JwtAuthModule,
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: AccessToken.name, schema: AccessTokenSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
    ]),
  ],
  exports: [CredentialsService],
  providers: [CredentialsService],
})
export class CredentialsAuthModule {}
