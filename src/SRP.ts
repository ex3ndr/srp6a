import { randomBytes } from 'universal-secure-random';
import { SRPParams, createSRPEngine } from './SRPParams';
import { SRPEngine } from './engine/SRPEngine';
import { bigIntToArray, arrayToBigInt } from './engine/convert';

export type SRPKeyPair = { secretKey: Uint8Array, publicKey: Uint8Array };

export type SRPSession = { sessionKey: Uint8Array, serverProof: Uint8Array, clientProof: Uint8Array };

export class SRP {
    private readonly _engine: SRPEngine;

    constructor(params: SRPParams) {
        this._engine = createSRPEngine(params);
    }

    /**
     * Generate User Salt
     * @param length Length of salt. Default is 16.
     */
    generateSalt(length: number = 16) {
        return randomBytes(length);
    }

    /**
     * Compute private key for a user
     * @param username Username
     * @param password Password
     * @param salt User's salt
     */
    computePrivateKey(username: string, password: string, salt: Uint8Array): Uint8Array {
        let x = this._engine.computeX(username, password, salt);
        return bigIntToArray(x); // No need to pad since it is used as bigint everywhere
    }

    /**
     * Compute verifier for a user
     * @param username Username
     * @param password Password
     * @param salt User's salt
     */
    computeVerifier(username: string, password: string, salt: Uint8Array): Uint8Array {
        let x = this._engine.computeX(username, password, salt);
        let v = this._engine.computeV(x);
        return bigIntToArray(v); // No need to pad since it is used as bigint everywhere
    }

    /**
     * Generate Client Ephemeral Key
     */
    generateClientEphemeralKey(): SRPKeyPair {
        const secretKey = randomBytes(this._engine.Nbytes);
        const publicKey = bigIntToArray(this._engine.computeA(arrayToBigInt(secretKey)));
        return {
            secretKey,
            publicKey
        };
    }

    /**
     * Generate Server Ephemeral Key
     * @param verifier User's verifier
     */
    generateServerEphemeralKey(verifier: Uint8Array): SRPKeyPair {
        const secretKey = randomBytes(this._engine.Nbytes);
        const publicKey = bigIntToArray(this._engine.computeB(arrayToBigInt(secretKey), arrayToBigInt(verifier)));
        return {
            secretKey,
            publicKey
        };
    }

    /**
     * Compute client session
     * @param key Client KeyPair
     * @param serverPublicKey Server Public Key
     * @param username Username
     * @param salt User's salt
     * @param privateKey User's private key
     * @returns Client Session or Null if something went wrong
     */
    computeClientSession(key: SRPKeyPair, serverPublicKey: Uint8Array, username: string, salt: Uint8Array, privateKey: Uint8Array): SRPSession | null {

        const a = arrayToBigInt(key.secretKey);
        const A = arrayToBigInt(key.publicKey);
        const B = arrayToBigInt(serverPublicKey);
        const x = arrayToBigInt(privateKey);

        // As in design: http://srp.stanford.edu/design.html
        if (B.mod(this._engine.N).eq(0)) {
            return null;
        }

        // 1. Random scrambling parameter
        const u = this._engine.computeU(A, B);
        // As in design: http://srp.stanford.edu/design.html
        if (u.mod(this._engine.N).eq(0)) {
            return null;
        }

        // 2. Session Key
        const S = this._engine.computeClientS(a, B, x, u);
        // 3. Strong Session Key
        const K = this._engine.computeK(S);
        // 4. Client Proof
        const M = this._engine.computeClientProof(username, salt, A, B, K);
        // 5. Server Proof
        const M2 = this._engine.computeServerProof(A, M, K);

        return {
            sessionKey: bigIntToArray(S),
            clientProof: bigIntToArray(M),
            serverProof: bigIntToArray(M2)
        };
    }

    computeServerSession(key: SRPKeyPair, clientPublicKey: Uint8Array, username: string, verifier: Uint8Array, salt: Uint8Array): SRPSession | null {
        const b = arrayToBigInt(key.secretKey);
        const B = arrayToBigInt(key.publicKey);
        const A = arrayToBigInt(clientPublicKey);
        const v = arrayToBigInt(verifier);

        // As in design: http://srp.stanford.edu/design.html
        if (A.mod(this._engine.N).eq(0)) {
            return null;
        }

        // 1. Random scrambling parameter
        const u = this._engine.computeU(A, B);
        // As in design: http://srp.stanford.edu/design.html
        if (u.mod(this._engine.N).eq(0)) {
            return null;
        }

        // 2. Session Key
        const S = this._engine.computeServerS(b, A, v, u);
        // 3. Strong Session Key
        const K = this._engine.computeK(S);
        // 4. Client Proof
        const M = this._engine.computeClientProof(username, salt, A, B, K);
        // 5. Server Proof
        const M2 = this._engine.computeServerProof(A, M, K);

        return {
            sessionKey: bigIntToArray(S),
            clientProof: bigIntToArray(M),
            serverProof: bigIntToArray(M2)
        };
    }
}