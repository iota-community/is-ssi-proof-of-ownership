import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as ed from '@noble/ed25519';
import * as bs58 from 'bs58';

@Injectable()
export class AppService {

  constructor(
    private httpService: HttpService,
    private configService: ConfigService
  ) {}

  async prove(did: string, timestamp: number, signature: string) {
    let rootEndpoint = this.configService.get("INTEGRATION_SERVICE", "https://ensuresec.solutions.iota.org");
    let response = await firstValueFrom(this.httpService.request({
      method: "get",
      url: `${rootEndpoint}/api/v0.1/verification/latest-document/${did}`,
      params: {
        "api-key": this.configService.get("API_KEY")
      }
    }))
    if (response.status !== 200) {
      throw new Error(response.data);
    }
    let identity = response?.data?.document;
    if (!identity) {
      throw new Error("Identity not found");
    }
    if (identity?.authentication?.length !== 1) {
      throw new Error("Expecting an identity with a single authentication method")
    }
    if (identity?.authentication?.[0]?.type !== "Ed25519VerificationKey2018") {
      throw Error("Signature not recognized: " + identity?.authentication?.type);
    }
    if (new Date().getTime() - timestamp < 0) {
      throw new Error("Bad timestamp: " + timestamp);
    }
    if (new Date().getTime() - timestamp > Number.parseInt(this.configService.get("EXPIRATION_TIME_MS"))) {
      throw new Error("Nonce expired");
    }
    const publicKeyBase58 = identity?.authentication?.[0]?.publicKeyBase58;
    const publicKey = bs58.decode(publicKeyBase58);
    const isVerified = await ed.verify(Buffer.from(signature, "hex"), Buffer.from(timestamp.toString()), publicKey);
    return isVerified;
  }

  getHealth(): string {
    return 'OK';
  }
}
