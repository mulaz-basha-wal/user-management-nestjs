import { ConsoleLogger, Injectable } from '@nestjs/common';
import * as fs from 'fs';
import { promises as fsPromises } from 'fs';
import * as path from 'path';

@Injectable()
export class MyLogger extends ConsoleLogger {
  private getFormattedDate(): string {
    const date = new Date();
    const formattedDate = new Intl.DateTimeFormat('en-IN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      timeZone: 'Asia/Kolkata',
    })
      .format(date)
      .replace(/\//g, '-');
    return formattedDate;
  }

  private async logToFile(entry: string) {
    const formattedDate = this.getFormattedDate();
    const formattedEntry = `${Intl.DateTimeFormat('en-IN', { dateStyle: 'short', timeStyle: 'short', timeZone: 'Asia/Kolkata' }).format(new Date())}\t${entry}\n`;
    const logsDir = path.join(__dirname, '..', '..', 'logs');

    try {
      if (!fs.existsSync(logsDir)) {
        await fsPromises.mkdir(logsDir, { recursive: true });
      }
      const logFileName = `${formattedDate}.log`;
      await fsPromises.appendFile(
        path.join(logsDir, logFileName),
        formattedEntry,
      );
    } catch (e) {
      if (e instanceof Error) console.error(e.message);
    }
  }

  log(message: any, context?: string) {
    const entry = `${context || 'Log'}\t${message}`;
    this.logToFile(entry);
    super.log(message, context);
  }

  error(message: any, stackOrContext?: string) {
    const entry = `${stackOrContext || 'Error'}\t${message}`;
    this.logToFile(entry);
    super.error(message, stackOrContext);
  }
}
