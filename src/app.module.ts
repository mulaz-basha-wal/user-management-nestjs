import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigService, ConfigModule as EnvConfigModule } from '@nestjs/config';
import { configuration, validationSchema } from './config';
import { UserModule } from './user/user.module';
import { MongooseModule } from '@nestjs/mongoose';
import { LoggerModule } from './my-logger/my-logger.module';

@Module({
  imports: [
    EnvConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema,
    }),
    MongooseModule.forRootAsync({
      imports: [EnvConfigModule],
      inject: [ConfigService],
      useFactory: async (config: ConfigService) => ({
        uri: config.get<string>('MONGODB_URI'),
      }),
    }),
    UserModule,
    LoggerModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
