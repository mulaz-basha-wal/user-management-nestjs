export const CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'Strict',
};

export const OAUTH_PROVIDERS = {
  GOOGLE: 'google',
};
