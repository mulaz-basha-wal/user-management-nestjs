import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { MyLogger } from './my-logger/my-logger.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.setGlobalPrefix('/api');
  app.useGlobalPipes(new ValidationPipe());
  app.useLogger(app.get(MyLogger));
  const configService = app.get(ConfigService);
  await app.listen(configService.getOrThrow('PORT'), () => {
    console.log(`${configService.get('APP_NAME')} application started..`);
  });
}
bootstrap();
