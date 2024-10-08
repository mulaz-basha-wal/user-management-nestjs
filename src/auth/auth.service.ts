import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/schemas/user.schema';
import { GoogleUser, LoginUser } from './interfaces/auth.interface';
import { MyLogger } from 'src/my-logger/my-logger.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import {
  AUTH_PROVIDERS,
  expiresTimeTokenMilliseconds,
} from './constants/auth.constants';
import { CookieOptions, Request } from 'express';
import { Response } from 'express';
import axios from 'axios';
import { ERROR_MESSAGES } from 'src/common/constants/user.constants';
import * as bcrypt from 'bcrypt';
import { errorHandler } from 'src/common/utils/apiErrorHandler';
import { Token } from 'src/schemas/token.schema';
import { UpdateUserDTO } from 'src/user/dto/userDTOs';
import { MailService } from './service/mail.service';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(Token.name) private tokenModel: Model<Token>,
    private configService: ConfigService,
    private jwtService: JwtService,
    private mailService: MailService,
  ) {}
  private logger = new MyLogger();

  async loginUser(loginUser: LoginUser, res: Response) {
    try {
      const { email, password } = loginUser;
      const user = await this.userModel.findOne({
        email: { $regex: new RegExp(`^${email}$`, 'i') },
      });
      if (!user) {
        throw new UnauthorizedException(ERROR_MESSAGES.INVALID_CREDENTIALS);
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException(ERROR_MESSAGES.INVALID_CREDENTIALS);
      }
      const payload = { userId: user._id, email: user.email };
      const accessToken = this.jwtService.sign(payload);
      await this.updateUserToken(
        user._id.toString(),
        AUTH_PROVIDERS.JWT,
        accessToken,
      );
      this.setTokenToCookies(
        res,
        accessToken,
        AUTH_PROVIDERS.JWT,
        user._id.toString(),
      );
      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      errorHandler(error, ERROR_MESSAGES.LOGIN_FAILED);
    }
  }

  //Goggle services
  async signInWithGoogle(user: GoogleUser, res: Response) {
    if (!user) throw new BadRequestException('Unauthenticated');
    let existingUser = await this.findUserByEmail(user.email);
    if (!existingUser) {
      existingUser = await this.registerGoogleUser(res, user);
      await this.updateUserToken(
        existingUser._id.toString(),
        AUTH_PROVIDERS.GOOGLE,
        user.accessToken,
        user.refreshToken,
      );
    } else {
      await this.updateUserToken(
        existingUser._id.toString(),
        AUTH_PROVIDERS.GOOGLE,
        user.accessToken,
      );
    }

    this.setTokenToCookies(
      res,
      user.accessToken,
      AUTH_PROVIDERS.GOOGLE,
      existingUser._id.toString(),
    );
    return user;
  }

  private async registerGoogleUser(res: Response, user: GoogleUser) {
    try {
      const newUser = await this.userModel.create({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        accessToken: user.accessToken,
      });
      return newUser;
    } catch (error) {
      this.logger.error(error);
      throw new InternalServerErrorException();
    }
  }

  async getGoogleTokenInfo(accessToken: string) {
    try {
      const response = await axios.get(
        `https://oauth2.googleapis.com/tokeninfo?access_token=${accessToken}`,
      );
      return response.data;
    } catch (error) {
      console.error(
        'Error fetching token info:',
        error.response?.data || error.message,
      );
      return error.response?.data || error.message;
    }
  }

  async getGoogleRefreshAccessToken(refreshToken: string): Promise<string> {
    const params = new URLSearchParams();
    params.append('client_id', process.env.GOOGLE_CLIENT_ID);
    params.append('client_secret', process.env.GOOGLE_CLIENT_SECRET);
    params.append('refresh_token', refreshToken);
    params.append('grant_type', 'refresh_token');

    try {
      const response = await axios.post(
        'https://oauth2.googleapis.com/token',
        params.toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );

      const { access_token } = response.data;
      return access_token;
    } catch (error) {
      console.error(
        'Error getting access token:',
        error.response?.data || error.message,
      );
      throw new Error('Unable to get access token');
    }
  }

  async revokeGoogleToken(token: string) {
    try {
      await axios.post(
        `${process.env.GOOGLE_AUTH_ENDPOINT}/revoke?token=${token}`,
      );
    } catch (error) {
      this.logger.error('Failed to revoke the token.');
    }
  }

  async validateUserWithGoogle(
    token: string,
    userId: string,
    res: Response,
  ): Promise<any> {
    try {
      let accessToken = token;
      const tokenInfo = await this.getGoogleTokenInfo(accessToken);
      const userDetails = await this.userModel.findById(userId);
      const userToken = await this.findUserTokenByProvider(userId, 'google');
      if (
        tokenInfo.expires_in / 60 < 5 ||
        tokenInfo.error === 'invalid_token'
      ) {
        accessToken = await this.getGoogleRefreshAccessToken(
          userToken.refreshToken,
        );
        await this.updateUserToken(userDetails.id, 'google', accessToken);
        this.setTokenToCookies(res, accessToken, 'google', userId);
      }
      const response = await axios.get(
        `https://www.googleapis.com/oauth2/v1/userinfo?alt=json`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      );
      let user = response.data;
      user = await this.userModel.findOne({ email: user.email });
      return { user };
    } catch (error) {
      this.logger.error('Error validating Google user:', error);
      throw new InternalServerErrorException('Could not validate Google user');
    }
  }

  //Linkedin services
  async signInWithLinkedin(user: any, res: Response) {
    if (!user) throw new BadRequestException('Unauthenticated');
    let existingUser = await this.findUserByEmail(user.email);
    if (!existingUser) {
      existingUser = await this.registerLinkedinUser(res, user);
      await this.updateUserToken(
        existingUser._id.toString(),
        AUTH_PROVIDERS.LINKEDIN,
        user.accessToken,
        user.refreshToken || null,
      );
    } else {
      await this.updateUserToken(
        existingUser._id.toString(),
        AUTH_PROVIDERS.LINKEDIN,
        user.accessToken,
      );
    }

    this.setTokenToCookies(
      res,
      user.accessToken,
      AUTH_PROVIDERS.LINKEDIN,
      existingUser._id.toString(),
    );
    return user;
  }

  private async registerLinkedinUser(res: Response, user: any) {
    try {
      const newUser = await this.userModel.create({
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        accessToken: user.accessToken,
      });
      return newUser;
    } catch (error) {
      this.logger.error(error);
      throw new InternalServerErrorException();
    }
  }

  async getLinkedinTokenInfo(accessToken: string) {
    try {
      const response = await axios.post(
        'https://www.linkedin.com/oauth/v2/introspectToken',
        new URLSearchParams({
          client_id: process.env.LINKEDIN_CLIENT_ID,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET,
          token: accessToken,
        }).toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );
      return response.data;
    } catch (error) {
      console.error(
        'Error fetching token info:',
        error.response?.data || error.message,
      );
      return error.response?.data || error.message;
    }
  }

  async revokeLinkedinToken(token: string) {
    try {
      await axios.post(
        'https://www.linkedin.com/oauth/v2/revoke',
        new URLSearchParams({
          client_id: process.env.LINKEDIN_CLIENT_ID,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET,
          token: token,
        }).toString(),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      );
    } catch (error) {
      this.logger.error('Failed to revoke the token.');
    }
  }

  async validateUserWithLinkedin(
    token: string,
    userId: string,
    res: Response,
  ): Promise<any> {
    try {
      const accessToken = token;
      const tokenInfo = await this.getLinkedinTokenInfo(accessToken);
      // const userToken = await this.findUserTokenByProvider(userId, 'linkedin');
      if (!tokenInfo.active) {
        // TODO:Get new accesstoken-refreshtoken not provided so not handled for now
        // );
        // await this.updateUserToken(userDetails.id, 'linkedin', accessToken);
        // this.setTokenToCookies(res, accessToken, 'linkedin', userId);
        throw new UnauthorizedException('Revoked access/session expired');
      }
      const response = await axios.get(`https://api.linkedin.com/v2/userinfo`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      let user = response.data;
      user = await this.userModel.findOne({ email: user.email });
      return { user };
    } catch (error) {
      this.logger.error('Error validating Linkedin user:', error);
      throw new InternalServerErrorException(
        'Could not validate Linkedin user',
      );
    }
  }

  // common services
  private async findUserByEmail(email: string) {
    const user = await this.userModel.findOne({ email });
    if (!user) return null;
    return user;
  }

  setTokenToCookies(
    res: Response,
    token: string,
    provider: string,
    userId: string,
  ) {
    const expirationDateInMilliseconds =
      new Date().getTime() + expiresTimeTokenMilliseconds;
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      expires: new Date(expirationDateInMilliseconds),
    };

    res.cookie('token', token, cookieOptions);
    res.cookie('provider', provider, cookieOptions);
    res.cookie('userId', userId, cookieOptions);
  }

  async updateUserToken(
    userId: string,
    authProvider: string,
    accessToken: string = null,
    refreshToken: string = null,
    resetPasswordToken: string = null,
    resetPasswordExpiryDate: Date = null,
  ) {
    const data = {
      userId,
      authProvider,
      accessToken,
      refreshToken,
      resetPasswordToken,
      resetPasswordExpiryDate,
    };
    const userToken = await this.tokenModel.findOne({
      userId,
      authProvider,
    });
    if (!userToken) {
      await this.tokenModel.create(data);
    } else {
      userToken.accessToken = accessToken || userToken.accessToken;
      userToken.refreshToken = refreshToken || userToken.refreshToken;
      userToken.resetPasswordToken =
        resetPasswordToken || userToken.resetPasswordToken;
      userToken.resetPasswordExpiryDate =
        resetPasswordExpiryDate || userToken.resetPasswordExpiryDate;
      await userToken.save();
    }
  }

  async getUserProvidersList(userId: string) {
    let providers = [];
    const tokens = await this.tokenModel.find({ userId });
    providers = tokens
      .map((token) => token.authProvider)
      .filter((provider, index, self) => self.indexOf(provider) === index);
    return providers;
  }

  async findUserTokenByProvider(userId: string, provider: string) {
    try {
      const userToken = await this.tokenModel.findOne({
        userId,
        authProvider: provider,
      });
      return userToken;
    } catch (e) {
      throw e;
    }
  }

  async validateUserWithJWT(token: string, userId: string): Promise<any> {
    try {
      const decodedToken = await this.jwtService.verifyAsync(token);
      const { userId } = decodedToken;
      const user = await this.userModel.findById(userId);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      return { user };
    } catch (error) {
      throw new UnauthorizedException(
        'Invalid token or user validation failed',
      );
    }
  }

  //Profile Management services
  async updatePassword(
    req: Request,
    body: {
      oldPassword: string;
      newPassword: string;
      confirmNewPassword: string;
    },
  ) {
    const { oldPassword, newPassword, confirmNewPassword } = body;
    const user = req.user as any;
    if (!newPassword || !confirmNewPassword) {
      throw new BadRequestException('Please provide all required fields');
    }
    if (user.user.password) {
      if (oldPassword) {
        const isOldPasswordValid = await bcrypt.compare(
          oldPassword,
          user.user.password,
        );
        if (!isOldPasswordValid) {
          throw new UnauthorizedException('Old password is incorrect');
        }
        if (newPassword === oldPassword) {
          throw new BadRequestException(
            'New password and and Old password Cannot be same',
          );
        }
      } else {
        throw new BadRequestException('Old password required');
      }
    }

    if (newPassword !== confirmNewPassword) {
      throw new BadRequestException(
        'New password and confirm password do not match',
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.updateUserToken(user.user.id, AUTH_PROVIDERS.JWT);

    return await this.userModel.updateOne(
      { email: user.user.email },
      { $set: { password: hashedPassword } },
    );
  }

  async forgotPassword(email: string) {
    const user = await this.findUserByEmail(email);
    if (!user) {
      throw new NotFoundException('User with this email does not exist');
    }
    const resetToken = uuidv4();
    const userToken = await this.findUserTokenByProvider(
      user.id,
      AUTH_PROVIDERS.JWT,
    );
    const resetTokenExpiration = new Date(Date.now() + 3600000); //1 hr
    await this.updateUserToken(
      user.id,
      AUTH_PROVIDERS.JWT,
      userToken?.accessToken || null,
      userToken?.refreshToken || null,
      resetToken,
      resetTokenExpiration,
    );

    const resetLink = `${process.env.RESET_PASSWORD_URL}?token=${resetToken}&userId=${user.id}`;
    await this.mailService.sendMail({
      to: email,
      subject: 'Reset Password',
      text: `You requested a password reset.It Will expire in an Hour. Click the link to reset your password: ${resetLink}`,
    });

    return true;
  }

  async updateProfile(email: string, updatedUser: UpdateUserDTO) {
    try {
      const user = await this.userModel.findOne({ email });
      if (!user) throw new ConflictException(ERROR_MESSAGES.USER_NOT_EXIST);
      return await this.userModel.findOneAndUpdate({ email }, updatedUser, {
        new: true,
      });
    } catch (error) {
      errorHandler(error, ERROR_MESSAGES.USER_UPDATE_FAILED);
    }
  }

  async verifyResetPasswordLink(token: string, userId: string) {
    const userToken = await this.findUserTokenByProvider(
      userId,
      AUTH_PROVIDERS.JWT,
    );
    if (!userToken || userToken.resetPasswordToken !== token) {
      throw new BadRequestException('Invalid or expired reset password link.');
    }

    if (userToken.resetPasswordExpiryDate < new Date()) {
      throw new BadRequestException('Reset password link  has expired.');
    }
    return true;
  }

  async resetPassword(
    token: string,
    userId: string,
    newPassword: string,
    confirmPassword: string,
  ) {
    const userToken = await this.findUserTokenByProvider(
      userId,
      AUTH_PROVIDERS.JWT,
    );
    if (!userToken || userToken.resetPasswordToken !== token) {
      throw new BadRequestException('Invalid or expired reset password link.');
    }

    if (userToken.resetPasswordExpiryDate < new Date()) {
      throw new BadRequestException('Reset password link  has expired.');
    }

    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Passwords do not match.');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await this.userModel.updateOne(
      { _id: userId },
      { $set: { password: hashedPassword } },
    );

    userToken.resetPasswordExpiryDate = null;
    userToken.resetPasswordToken = null;

    await userToken.save();

    return { message: 'Password reset successful' };
  }
}
