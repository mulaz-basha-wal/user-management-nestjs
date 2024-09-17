import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OAUTH_PROVIDERS } from '../auth.constants';

@Injectable()
export class GoogleOauthStrategy extends PassportStrategy(
  Strategy,
  OAUTH_PROVIDERS.GOOGLE,
) {
  constructor(configService: ConfigService) {
    super({
      clientID: configService.get('GOOGLE_OAUTH_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_OAUTH_CLIENT_SECRET'),
      callbackURL: configService.get('GOOGLE_OAUTH_REDIRECT_URL'),
      scope: ['email', 'profile'],
    });
  }

  // required to get the refresh token
  authorizationParams(): { [key: string]: string } {
    return {
      access_type: 'offline',
      prompt: 'select_account',
    };
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: any,
  ) {
    const { name, emails, photos } = profile;
    const user = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
      picture: photos[0].value,
      _accessToken,
      _refreshToken,
    };

    done(null, user);
  }
}
