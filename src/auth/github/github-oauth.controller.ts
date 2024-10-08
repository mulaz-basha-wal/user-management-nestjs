import { Response } from 'express';
import { Controller, Get, Request, Res, UseGuards } from '@nestjs/common';
import { GithubConsentGuard, GithubOAuthGuard } from './github-oauth.guard';
import { GithubOAuthService } from './github-oauth.service';

@Controller('auth/github')
export class GithubOAuthController {
  constructor(private githubOAuthService: GithubOAuthService) {}

  @Get()
  @UseGuards(GithubConsentGuard, GithubOAuthGuard)
  async githubLogin() {}

  @Get('callback')
  @UseGuards(GithubOAuthGuard)
  async githubCallback(@Request() req, @Res() res: Response) {
    this.githubOAuthService.loginCallback(req, res);
    return {};
  }
}
