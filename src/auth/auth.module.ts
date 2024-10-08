import { forwardRef, Module } from '@nestjs/common';
import { GoogleOauthModule } from './google/google-oauth.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthModule } from './jwt/jwt.module';
import { UserModule } from 'src/auth/user/user.module';
import { CredentialsAuthModule } from './credentials/credentials.module';
import { GithubOAuthModule } from './github/github-oauth.module';
import { MailService } from 'src/mail/mail.service';

@Module({
  imports: [
    JwtAuthModule,
    GoogleOauthModule,
    GithubOAuthModule,
    CredentialsAuthModule,
    forwardRef(() => UserModule),
  ],
  controllers: [AuthController],
  providers: [AuthService, MailService],
  exports: [AuthService],
})
export class AuthModule {}
