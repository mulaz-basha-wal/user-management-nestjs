import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
  private logger: Logger = new Logger('HttpLogger');

  use(request: Request, response: Response, next: NextFunction): void {
    const { method, baseUrl } = request;
    this.logger.log(`${method} - ${baseUrl}`);
    next();
  }
}
