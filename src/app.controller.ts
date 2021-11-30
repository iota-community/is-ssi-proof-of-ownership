import { Body, Controller, Get, Post } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post("/api/v1/ownership/prove")
  async prove(@Body() body: any) {
    try {
      const { did, timestamp, signature } = body;
      let isVerified = await this.appService.prove(did, Number.parseInt(timestamp), signature);
      return {
        success: true,
        isVerified
      }
    }
    catch (e) {
      return {
        success: false,
        error: e?.response?.data?.error ? e.response.data.error : e.message
      }
    }
  }

  @Get("/health")
  getHealth(): string {
    return this.appService.getHealth();
  }
}
