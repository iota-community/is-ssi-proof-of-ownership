import * as ed from '@noble/ed25519';
import * as bs58 from 'bs58';

async function example() {

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
    const signatureBuffer = await ed.sign(Buffer.from(timestamp.toString()), privateKey);
    const signature = Buffer.from(signatureBuffer).toString("hex")

    console.log()
    console.log("This is an example of signed payload:");
    console.log({
        did,
        timestamp,
        signature: signature
    })

    console.log()
    console.log("You can try with the following cURL:");
    console.log("curl --header \"Content-Type: application/json\" \\");
    console.log("  --request POST \\");
    console.log("  --data '" + JSON.stringify({
        did,
        timestamp,
        signature: signature
    }) + "' \\");
    console.log("  http://localhost:4000/api/v1/ownership/prove");

}

example().then(console.log).catch(console.log)