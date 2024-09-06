export const configuration = () => ({
  PORT: parseInt(process.env.PORT),
  NODE_ENV: process.env.NODE_ENV,
  APP_NAME: process.env.APP_NAME,
});
