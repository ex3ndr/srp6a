# SRP-6a implementation for js
Modular implementation of [Secure Remote Password](http://srp.stanford.edu/) protocol for NodeJS/Browser/React Native environments. This library is inspired by NaCl crypto library and tries to provide same safety and simplicity to the user.

This library is a little bit opioniated about how pefrom authentication process i believe that this process covers all cases and if it doesn't match your project, please, open an issue an i will implement an alternative way or suggest work-around.

## Features
* 💪Secure default settings
* 🚀Fast and Safe SRP Engine that conforms to RFC 5054
* 🦺SRP Server and Client that is safe to use without need of a deep knowledge of SRP
* 🧐Customizations for password hashing and proof calculation

# Getting Started

## Install
```bash
yarn add srp6a
```

## Configuration
To use this library you have to configure SRP parameters and provide secure pseudorandom number generator. 
For simplicity you can pick default parameters and default nodejs random number generator:

```js
import { SRP } from 'srp6a';
import crypto from 'crypto';

const srp = new SRP('default', crypto.randomBytes);
```

## Compute Verifier
For each user you have to generate random salt and store it in the database. Salt is not secret and could be treated the same way as a username.

```js
const username = 'ex3ndr';
const password = '12345678';
const salt = srp.generateSalt();
const verifier = srp.computeVerifier(username, password, salt);
```

## Authentication process
For authentication there are 'SRPClient' and 'SRPServer' classes. **Beware: they are can't be reused!**. After failed or successful negotiation any function call will result in exception being thrown.
If any function return false then 'SRPClient'/'SRPServer' will turn into failed state and could not be used anymore and you have to start new authentication session.

```js
const srpClient = new SRPClient('default', crypto.randomBytes);
const srpServer = new SRPServer('default', crypto.randomBytes);
```

### Set Credentials
First step is setting credentials on client and on server sides:
```js
if (!client.setCredentials(username, password, salt)) {
  throw Error('Unable to set client credentials');
}
if (!server.setCredentials(username, verifier, salt)) {
  throw Error('Unable to set server credentials');
}
```

### Exchange Ephemeral Keys
After setting credentials new ephemeral keys are generated and they became available in `publicKey` property. **This property will throw error if you haven't set credentials.**
```js
if (!client.setServerKey(server.publicKey)) {
  throw Error('Unable to set server public key');
}
if (!server.setClientKey(client.publicKey)) {
  throw Error('Unable to set client public key');
}
```



### Validate Proofs
To get an acccess to Session Key you have to validate proofs. Server-side proof is **not** available untill you successfully validated client one.
```js
if (!server.validateProof(client.proof)) {
    throw Error('Invalid client proof');
}
if (!client.validateProof(server.proof)) {
    throw Error('Invalid server proof');
}
```

### Session Key
After validation you can retreive session key:
```js
const sessionKey = client.sessionKey;
```
```js
const sessionKey = server.sessionKey;
```

# License
[MIT](LICENSE)
