import { randomBytes } from 'universal-secure-random';
import { SRPParams, createSRPEngine } from './SRPParams';
import { SRPEngine } from './engine/SRPEngine';
import { bigIntToBuffer, bufferToBigInt } from './engine/convert';

export type SRPKeyPair = { secretKey: Buffer, publicKey: Buffer };

export type SRPSession = { sessionKey: Buffer, serverProof: Buffer, clientProof: Buffer };

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
    computePrivateKey(username: string, password: string, salt: Buffer): Buffer {
        let x = this._engine.computeX(username, password, salt);
        return bigIntToBuffer(x); // No need to pad since it is used as bigint everywhere
    }

    /**
     * Compute verifier for a user
     * @param username Username
     * @param password Password
     * @param salt User's salt
     */
    computeVerifier(username: string, password: string, salt: Buffer): Buffer {
        let x = this._engine.computeX(username, password, salt);
        let v = this._engine.computeV(x);
        return bigIntToBuffer(v); // No need to pad since it is used as bigint everywhere
    }

    /**
     * Generate Client Ephemeral Key
     */
    generateClientEphemeralKey(): SRPKeyPair {
        const secretKey = randomBytes(this._engine.Nbytes);
        const publicKey = bigIntToBuffer(this._engine.computeA(bufferToBigInt(secretKey)));
        return {
            secretKey,
            publicKey
        };
    }

    /**
     * Generate Server Ephemeral Key
     * @param verifier User's verifier
     */
    generateServerEphemeralKey(verifier: Buffer): SRPKeyPair {
        const secretKey = randomBytes(this._engine.Nbytes);
        const publicKey = bigIntToBuffer(this._engine.computeB(bufferToBigInt(secretKey), bufferToBigInt(verifier)));
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
    computeClientSession(key: SRPKeyPair, serverPublicKey: Buffer, username: string, salt: Buffer, privateKey: Buffer): SRPSession | null {

        const a = bufferToBigInt(key.secretKey);
        const A = bufferToBigInt(key.publicKey);
        const B = bufferToBigInt(serverPublicKey);
        const x = bufferToBigInt(privateKey);

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
            sessionKey: bigIntToBuffer(S),
            clientProof: bigIntToBuffer(M),
            serverProof: bigIntToBuffer(M2)
        };
    }

    computeServerSession(key: SRPKeyPair, clientPublicKey: Buffer, username: string, verifier: Buffer, salt: Buffer): SRPSession | null {
        const b = bufferToBigInt(key.secretKey);
        const B = bufferToBigInt(key.publicKey);
        const A = bufferToBigInt(clientPublicKey);
        const v = bufferToBigInt(verifier);

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
            sessionKey: bigIntToBuffer(S),
            clientProof: bigIntToBuffer(M),
            serverProof: bigIntToBuffer(M2)
        };
    }
}