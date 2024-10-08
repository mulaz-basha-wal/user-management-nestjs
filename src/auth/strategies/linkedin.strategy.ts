import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { InternalServerErrorException } from '@nestjs/common';
import axios from 'axios';
import { StrategiesEnum } from '../constants/strategies.constants';
import { MyLogger } from 'src/my-logger/my-logger.service';

export class LinkedinStrategy extends PassportStrategy(
  Strategy,
  StrategiesEnum.Linkedin,
) {
  private readonly logger = new MyLogger();

  constructor() {
    super();
  }

  async validate(req: any, done: any): Promise<any> {
    const { code } = req.query;

    try {
      const tokenResponse = await axios.post(
        'https://www.linkedin.com/oauth/v2/accessToken',
        null,
        {
          params: {
            grant_type: 'authorization_code',
            code,
            redirect_uri: `${process.env.BASE_URL}${process.env.LINKEDIN_REDIRECT_URL}`,
            client_id: process.env.LINKEDIN_CLIENT_ID,
            client_secret: process.env.LINKEDIN_CLIENT_SECRET,
          },
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      const accessToken = tokenResponse.data.access_token;

      const profileResponse = await axios.get(
        'https://api.linkedin.com/v2/userinfo',
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      );

      const profile = profileResponse.data;
      const user = {
        firstName: profile.given_name,
        lastName: profile.family_name,
        email: profile.email,
        accessToken: accessToken,
      };
      done(null, user);
    } catch (error) {
      this.logger.error('Error during LinkedIn OAuth process: ', error);
      const internalError = new InternalServerErrorException(
        'LinkedIn OAuth process failed',
      );
      done(internalError, false);
    }
  }
}
