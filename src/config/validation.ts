import * as Joi from 'joi';

export const validationSchema = Joi.object({
  PORT: Joi.number().required().min(3000),
  NODE_ENV: Joi.string().valid('development', 'production', 'test').required(),
  APP_NAME: Joi.string().min(2).optional(),
});
