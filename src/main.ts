import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { MyLogger } from './my-logger/my-logger.service';

async function bootstrap() {
  const cookieParser = require('cookie-parser');
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('/api');
  app.useGlobalPipes(new ValidationPipe());
  app.useLogger(app.get(MyLogger));
  app.use(cookieParser());
  app.enableCors({
    origin: ['http://localhost:3000'],
    credentials: true,
  });
  const configService = app.get(ConfigService);
  await app.listen(configService.getOrThrow('PORT'), () => {
    console.log(`${configService.get('APP_NAME')} application started..`);
  });
}
bootstrap();
