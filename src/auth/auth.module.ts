import { Module } from '@nestjs/common';
import { GoogleStrategy } from './strategies/google.strategy';
import { AuthController } from './auth.controller';
import { GoogleAuthGuard } from './guards/google.guard';
import { AuthService } from './auth.service';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from 'src/schemas/user.schema';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthGuard } from './guards/auth.guard';
import { Token, TokenSchema } from 'src/schemas/token.schema';
import { MailService } from './service/mail.service';
import { RoleGuard } from './guards/role.guard';
import { LinkedinAuthGuard } from './guards/linkedin.guard';
import { LinkedinStrategy } from './strategies/linkedin.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Token.name, schema: TokenSchema },
    ]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    GoogleStrategy,
    GoogleAuthGuard,
    AuthGuard,
    JwtModule,
    AuthService,
    AuthGuard,
    MailService,
    RoleGuard,
    LinkedinAuthGuard,
    LinkedinStrategy,
  ],
  exports: [AuthService],
})
export class AuthModule {}
