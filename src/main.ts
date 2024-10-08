import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { TOKEN_REFRESH_HEADER } from './auth/auth.constants';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  app.enableCors({
    origin: [configService.getOrThrow('CLIENT_URL')],
    exposedHeaders: [TOKEN_REFRESH_HEADER],
    credentials: true,
  });
  app.use(cookieParser());
  app.setGlobalPrefix('/api');
  app.useGlobalPipes(new ValidationPipe());
  await app.listen(configService.getOrThrow('PORT'));
}
bootstrap();
