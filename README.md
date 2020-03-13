# SRP-6a implementation for js
[![Version npm](https://img.shields.io/npm/v/srp6a.svg?logo=npm)](https://www.npmjs.com/package/srp6a)

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

# Advanced Configuration
### Presets
There are some built-in presets (please, make a PR for some other well-established parameters). To use a preset simply provide a name to SRP/SRPClient/SRPServer constructors as a first parameter.
* ```'default'``` - Default safe parameters: 2048 bit group from RFC 5054 and SHA-256 for hashing.
* ```'homekit'``` - HomeKit Accessory Protocol parameters: 3072 bit group from RFC 5054 and SHA-512 for hashing.

### Manual Configuration
If presets does not work for you, you can specify group and hashing algorithm manually:
```js
{ group: GROUP, hash: HASH }
```
Where `GROUP` could be one of:
* RFC 5054 groups:
  * 1024 bit: `'rfc5054_1024'`
  * 1536 bit: `'rfc5054_1536'`
  * 2048 bit: `'rfc5054_2048'`
  * 3072 bit: `'rfc5054_3072'`
  * 4096 bit: `'rfc5054_4096'`
  * 6144 bit: `'rfc5054_6144'`
  * 8192 bit: `'rfc5054_8192'`
* Custom Group: ```{ N: string, g: string }```. Both numbers are in HEX format with any number of space symbols and formatting.
Where `HASH` could be one of:
* Built-in hashing:
  * SHA-1: `'sha-1'`
  * SHA-256: `'sha-256'`
  * SHA-512: `'sha-512'`
* Custom hashing function of type: ``` (...src: (Buffer)[]) => Buffer ```
# License
[MIT](LICENSE)
