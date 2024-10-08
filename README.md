<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

[circleci-image]: https://img.shields.io/circleci/build/github/nestjs/nest/master?token=abc123def456
[circleci-url]: https://circleci.com/gh/nestjs/nest 'https://skillicons.dev'

<p align="center">
  <a href="https://skillicons.dev">
    <img src="https://skillicons.dev/icons?i=nodejs,ts,nestjs,mongodb,github,npm" />
  </a>
</p>
<p align="center">Basic <a href="https://github.com/nestjs/nest" target="_blank">Nest.js</a> service for users authorization and authentication using OAuth protocols.</p>

## Description

This repository features a User Management System developed with NestJS and MongoDB, providing complete functionality for user registration, login, and profile management. Built with the Nest framework and TypeScript, the project ensures a modular, scalable architecture and supports OAuth2 for authentication. Social sign-ins are implemented using the OAuth2 protocol, including Sign in with Google and GitHub authentication flows.

## Features

- User Sign-Up.
  - Username and Password
  - Register with Google (<a href="https://www.passportjs.org/packages/passport-google-oauth20" target="_blank">passport-google-oauth20</a>)
  - Register with Github (<a href="https://www.passportjs.org/packages/passport-github2" target="_blank">passport-github2</a>)
- User Sign-In.
  - Username and Password
  - Sign-In with Google (<a href="https://www.passportjs.org/packages/passport-google-oauth20" target="_blank">passport-google-oauth20</a>)
  - Sign-In with Github (<a href="https://www.passportjs.org/packages/passport-github2" target="_blank">passport-github2</a>)
- Access and Refresh Token management using JWT tokens and auto-refresh access tokens.
- Profile Management
  - Edit/update profile
  - Change password
  - Reset Password with email link (<a href="https://nodemailer.com/" target="_blank">Nodemailer</a>)
  - Forgot Password with email link (<a href="https://nodemailer.com/" target="_blank">Nodemailer</a>)
- Admin operations
  - Users list with pagination and search filter
  - Edit user
  - Block user
  - Delete User
  - Change Password

## Technologies Used
  - **NestJS:** A framework for building scalable NodeJs server-side applications.
  - **Mongoose:** For MongoDB database management and modeling.
  - **NodeMailer:** A module for sending emails.
  - **NestJs/jwt:** JWT token sign and verification.
  - **Argon2:** Argon2 is a cryptographic hashing algorithm used to hash passwords > bcrypt.
  - **passport:** A package for simplifying the OAuth flow in NodeJS.
  - **passport-google-oauth20:** This module lets you authenticate using Google in your NodeJs applications.
  - **passport-github2:** This module lets you authenticate using Github in your NodeJs applications.


## Installation

- Clone / Download this repository.
```bash
$ git clone <repo-link>
```
- Node version is required as per the .nvmrc file.
```bash
$ nvm use <node_version>
```
- Create a .env file and copy required environment variables from the .env.example
- Run the below command to install all the project dependencies.

```bash
$ npm install
```

## Running the app

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Test

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## Folder Structure
```bash
src/
|-- auth/                # Authentication logic with PassportJS and OAuth flow
|-- --- credentials/     # Username & password based auth flow
|-- --- github/          # Github module to manage OAuth flow
|-- --- google/          # Google module to manage OAuth flow
|-- --- jwt/             # JWT module to manage JWT tokens
|-- --- user/            # User module and its resource inside the folder
|-- --- auth.module      # Auth Module and its deps
|-- --- auth.service     # Core auth services
|-- --- auth.controller  # Auth routes and handlers
|-- --- auth.guard       # Authentication guards
|-- --- auth.constants   # Auth related constants
|-- schemas              # MongoDB collection schemas
|-- common/              # Common functionality folder
|-- --- constants/       # Applications related constants
|-- --- middlewares/     # Middlewares used in the application
|-- --- utilities/       # Common utility functions
|-- config               # Basic application configurations
|-- mail/                # Mail service to send emails for forgot and reset password
|-- --- templates        # HBS templates for emails
|-- --- mail.service     # Email sending logic
|-- app.module.ts        # Main application file
|-- main.ts              # Entry point of the application
```