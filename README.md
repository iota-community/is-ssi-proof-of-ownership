Microservice based on Integration Services and IOTA SSI that allow a client to prove its identity to a third party

## Description

Proof of ownership is a triple:
- an SSI identifier (DID), 
- a timestamp, 
- and a signature (obtained signing the timestamp with the identity's private key).
That triple can be provided to the microservice in order to prove the ownership of a given SSI.
Identity's public key is held in IOTA Tangle so it can be retrieved by validator and used to
verify that client owns the corresponding private key.

## How to use it

Using [httpie](https://httpie.io/):

```bash
$ http POST <service host>/api/v1/ownership/prove \
    did=<did:iota:...> \
    timestamp=<e.g. new Date().getTime()> \
    signature=<hex signature>
```

You can see an example of how a digital proof of ownership 
could be created looking in `example` directory.

You can see an example of how an invocation could be running:

```
$ npm run example 
```

This script will create an example of a payload that can be sent to microservice to prove ownership of an SSI identity (`did:iota:2xCZnoUYakpLYzSWXjwiebYp6RpiUi8DvD9DwoU3qeSz` hardcoded in the example).

## Installation

```bash
$ npm install
```

Copy env file
```bash
$ cp .env.example .env
```

Replace `.env` with reference to Integration Service api and its Api Key

## Running the service

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
## License

[Apache 2.0](LICENSE).
