import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('/api');
  const configService = app.get(ConfigService);
  await app.listen(configService.getOrThrow('PORT'), () => {
    console.log(`${configService.get('APP_NAME')} application started..`);
  });
}
bootstrap();
