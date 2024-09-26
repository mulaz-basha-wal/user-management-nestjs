import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule as EnvConfigModule } from '@nestjs/config';
import { configuration, validationSchema } from './config';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { LoggerModule } from './my-logger/my-logger.module';
import { AuthModule } from './auth/auth.module';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
  imports: [
    EnvConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema,
    }),
    MongooseModule.forRoot(process.env.MONGODB_URI),
    UserModule,
    LoggerModule,
    AuthModule,
    MailerModule.forRoot({
      transport: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.MAIL_USER,
          pass: process.env.MAIL_PASSWORD,
        },
      },
      defaults: {
        from: '"No Reply" <noreply@example.com>', // Default sender address
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
