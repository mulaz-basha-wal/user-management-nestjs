import { AuthModule } from '../auth.module';
import { forwardRef, Module } from '@nestjs/common';
import { UserModule } from 'src/auth/user/user.module';
import { GithubOAuthStrategy } from './github-oauth.strategy';
import { GithubOAuthController } from './github-oauth.controller';
import { GithubOAuthService } from './github-oauth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/schemas/user.schema';
import { JwtAuthModule } from '../jwt/jwt.module';
import { GithubToken, GithubTokenSchema } from 'src/schemas/githubToken.schema';

@Module({
  imports: [
    forwardRef(() => UserModule),
    forwardRef(() => AuthModule),
    JwtAuthModule,
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: GithubToken.name, schema: GithubTokenSchema },
    ]),
  ],
  controllers: [GithubOAuthController],
  providers: [GithubOAuthService, GithubOAuthStrategy],
  exports: [GithubOAuthService],
})
export class GithubOAuthModule {}
