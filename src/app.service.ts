import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import * as ed from 'noble-ed25519';
import * as bs58 from 'bs58';

@Injectable()
export class AppService {

  constructor(
    private httpService: HttpService,
    private configService: ConfigService
  ) {
    this.example();
  }

  async example() {

    let identity = {
      "_id": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz",
      "doc": {
        "id": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz",
        "verificationMethod": [
          {
            "id": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz#key-collection-0",
            "controller": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz",
            "type": "MerkleKeyCollection2021",
            "publicKeyBase58": "114pfYkC75dqSg3crfRxucmWwGo1x5325ZXKr2pHsm1c5u"
          }
        ],
        "authentication": [
          {
            "id": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz#key",
            "controller": "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz",
            "type": "Ed25519VerificationKey2018",
            "publicKeyBase58": "Auo3CpXUjvCf7yjPPrWhvRdsE4qAtvn5hLPBXNy2iFok"
          }
        ],
        "created": "2021-11-27T08:47:33Z",
        "updated": "2021-11-27T08:47:33Z",
        "previousMessageId": "b51bc89d583b5d4f22204238a0a5c7d66a28476c9f28f4f2470d9de537dda630",
        "proof": {
          "type": "JcsEd25519Signature2020",
          "verificationMethod": "#key",
          "signatureValue": "2MrtMZZYmKUrB2jdsG4hwzD6yxAjo3uUrnNq44uVFWd6p8zvaRqhwvfQV5keGdJXV57HS7V9djWM5ZSm8dwY7FNm"
        }
      },
      "key": {
        "type": "ed25519",
        "public": "Auo3CpXUjvCf7yjPPrWhvRdsE4qAtvn5hLPBXNy2iFok",
        "secret": "2mwf8CmHVR336TLQd5m1U6RS5MnKaVvhB2DiAUjgAMka",
        "encoding": "base58"
      },
      "txHash": "02bd9bf3f291b94ff10eef7de7122768db7d77bf9509b5fbd432f774ed63d7cd",
      "created": "2021-11-27T08:47:49.681Z"
    };

    const did = "did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz";
    const timestamp = new Date().getTime();
    const privateKey = bs58.decode(identity?.key?.secret);
    const signature = await ed.sign(Buffer.from(timestamp.toString()), privateKey);
    console.log({
      did,
      timestamp,
      signature: Buffer.from(signature).toString("hex")
    })
  }

  async prove(did: string, timestamp: number, signature: string) {
    let rootEndpoint = this.configService.get("INTEGRATION_SERVICE", "https://ensuresec.solutions.iota.org");
    let response = await firstValueFrom(this.httpService.request({
      method: "get",
      url: `${rootEndpoint}/api/v1/verification/latest-document/${did}`,
      params: {
        "api-key": this.configService.get("API_KEY")
      }
    }))
    console.log("response.request.data");
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
