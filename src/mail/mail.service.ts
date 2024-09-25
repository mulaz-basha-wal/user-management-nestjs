import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      secure: process.env.MAIL_SECURE?.toLowerCase() === 'true',
      auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
      },
    });
  }

  private compileTemplate(templateName: string, context: any): string {
    const filePath = path.join(__dirname, 'templates', `${templateName}.hbs`);
    const source = fs.readFileSync(filePath, 'utf-8');
    const template = handlebars.compile(source);
    return template(context);
  }

  async sendMail(
    to: string,
    subject: string,
    templateName: string,
    context: any,
  ) {
    const emailContent = this.compileTemplate(templateName, context);
    await this.transporter.sendMail({
      from: process.env.APP_NAME,
      to,
      subject,
      html: emailContent,
    });
  }
}
