import { Module } from '@nestjs/common';
import { GoogleOauthModule } from './google/google-oauth.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  controllers: [AuthController],
  imports: [GoogleOauthModule],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
