import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { InternalServerErrorException } from '@nestjs/common';
import { StrategiesEnum } from '../constants/strategies.constants';
import { MyLogger } from 'src/my-logger/my-logger.service';
import { GoogleUser } from '../interfaces/auth.interface';

export class GoogleStrategy extends PassportStrategy(
  Strategy,
  StrategiesEnum.Google,
) {
  constructor() {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}${process.env.GOOGLE_REDIRECT_URL}`,
      scope: ['email', 'profile'],
    });
  }
  authorizationParams(): { [key: string]: string } {
    return {
      access_type: 'offline',
    };
  }
  private readonly logger = new MyLogger();

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    try {
      const { name, emails, photos } = profile;
      const user: GoogleUser = {
        email: emails[0].value,
        firstName: name.givenName,
        lastName: name.familyName,
        picture: photos[0].value,
        accessToken,
        refreshToken,
      };
      done(null, user);
    } catch (error) {
      this.logger.error(error);
      const internalError = new InternalServerErrorException();
      done(internalError);
      throw internalError;
    }
  }
}
