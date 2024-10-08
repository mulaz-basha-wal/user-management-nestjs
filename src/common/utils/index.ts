import { Request } from 'express';

export function maskEmail(email: string) {
  const [localPart, domain] = email.split('@');

  if (localPart.length <= 2) {
    return `${localPart[0]}***@${domain}`;
  }
  const maskedLocalPart = `${localPart[0]}***${localPart[localPart.length - 1]}`;
  return `${maskedLocalPart}@${domain}`;
}

export function authorizationErrorLink(req: Request, provider: string) {
  const errMessage = 'The user has denied your application access.';
  const { error, error_description } = req.query as any;

  const errorDescription = `${error_description || errMessage}`;
  const query = new URLSearchParams({
    error,
    errorDescription,
    provider,
  }).toString();
  return `${process.env.CLIENT_URL}/auth_failed?${query}`;
}
