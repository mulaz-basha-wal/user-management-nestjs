import { Module } from '@nestjs/common';
// import { JwtAuthModule } from '../jwt/jwt-auth.module';
import { GoogleOauthController } from './google-oauth.controller';
import { GoogleOauthStrategy } from './google-oauth.strategy';
import { UserModule } from 'src/user/user.module';
import { GoogleOauthService } from './google-oauth.service';
import { AuthService } from '../auth.service';

@Module({
  imports: [UserModule],
  controllers: [GoogleOauthController],
  providers: [AuthService, GoogleOauthService, GoogleOauthStrategy],
})
export class GoogleOauthModule {}
