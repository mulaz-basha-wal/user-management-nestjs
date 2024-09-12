import { HttpException } from '@nestjs/common';

export const errorHandler = (
  error: any,
  message: string,
  statusCode: number = 500,
) => {
  throw new HttpException(
    {
      message,
      error: error.message,
    },
    statusCode,
  );
};
