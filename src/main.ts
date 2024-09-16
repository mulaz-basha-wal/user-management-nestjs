import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { MyLogger } from './my-logger/my-logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  app.enableCors({
    origin: [configService.getOrThrow('CLIENT_URL')],
    credentials: true,
  });
  app.use(cookieParser());
  app.setGlobalPrefix('/api');
  app.useGlobalPipes(new ValidationPipe());
  app.useLogger(app.get(MyLogger));
  await app.listen(configService.getOrThrow('PORT'), () => {
    console.log(`${configService.get('APP_NAME')} application started..`);
  });
}
bootstrap();
