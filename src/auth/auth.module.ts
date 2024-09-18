import { forwardRef, Module } from '@nestjs/common';
import { GoogleOauthModule } from './google/google-oauth.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthModule } from './jwt/jwt.module';
import { UserModule } from 'src/user/user.module';

@Module({
  imports: [GoogleOauthModule, JwtAuthModule, forwardRef(() => UserModule)],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
