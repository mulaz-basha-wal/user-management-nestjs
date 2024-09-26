export enum USER_ROLES {
  ADMIN = 1,
  USER = 2,
}

export const ERROR_MESSAGES = {
  USER_EXIST: 'User already exists.',
  USER_NOT_EXIST: 'User does not exists.',
  USER_FETCH_FAILED: 'Unable to fetch user(s).',
  USER_UPDATE_FAILED: 'Unable to update user.',
  USER_DELETE_FAILED: 'Unable to delete user.',
  USER_CREATION_FAILED: 'Unable to register, please try again after sometime.',
  PASSWORDS_DO_NOT_MATCH: 'Password and Confirm password did not match',
  INVALID_CREDENTIALS: 'Invalid email/password',
  LOGIN_FAILED: 'Login failed. Please try again',
};
