import { forwardRef, Module } from '@nestjs/common';
import { GoogleOauthController } from './google-oauth.controller';
import { GoogleOauthStrategy } from './google-oauth.strategy';
import { UserModule } from 'src/auth/user/user.module';
import { GoogleOauthService } from './google-oauth.service';
import { AuthModule } from '../auth.module';

@Module({
  imports: [forwardRef(() => UserModule), forwardRef(() => AuthModule)],
  controllers: [GoogleOauthController],
  providers: [GoogleOauthService, GoogleOauthStrategy],
  exports: [GoogleOauthService],
})
export class GoogleOauthModule {}
