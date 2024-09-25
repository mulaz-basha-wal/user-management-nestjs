export function maskEmail(email: string) {
  const [localPart, domain] = email.split('@');

  if (localPart.length <= 2) {
    return `${localPart[0]}***@${domain}`;
  }
  const maskedLocalPart = `${localPart[0]}***${localPart[localPart.length - 1]}`;
  return `${maskedLocalPart}@${domain}`;
}
