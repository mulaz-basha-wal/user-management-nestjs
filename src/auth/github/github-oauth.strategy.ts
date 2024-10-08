import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUTH_PROVIDERS } from '../auth.constants';
import { Strategy } from 'passport-github2';

@Injectable()
export class GithubOAuthStrategy extends PassportStrategy(
  Strategy,
  AUTH_PROVIDERS.GITHUB,
) {
  constructor(configService: ConfigService) {
    super({
      clientID: configService.get('GITHUB_OAUTH_CLIENT_ID'),
      clientSecret: configService.get('GITHUB_OAUTH_CLIENT_SECRET'),
      callbackURL: configService.get('GITHUB_OAUTH_REDIRECT_URL'),
      scope: ['user:email'],
    });
  }

  validate(accessToken: string, refreshToken: string, profile: any, done: any) {
    const Profile = profile._json;
    const user = {
      email: profile.emails[0].value,
      firstName: Profile.name,
      lastName: Profile.lastName || null,
      picture: Profile.avatar_url,
      accessToken,
      refreshToken: refreshToken || null,
    };

    done(null, user);
  }
}
