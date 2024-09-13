import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { GoogleOauthModule } from './google/google-oauth.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  controllers: [AuthController],
  imports: [UserModule, GoogleOauthModule],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
