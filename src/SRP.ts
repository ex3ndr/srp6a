import { BigInt } from './utils/BigInt';
import { randomBytes } from 'universal-secure-random';
import { SRPParams, createSRPEngine } from './SRPParams';
import { SRPEngine } from './engine/SRPEngine';

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
        return x.toBuffer(); // No need to pad since it is used as bigint everywhere
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
        return v.toBuffer(); // No need to pad since it is used as bigint everywhere
    }

    /**
     * Generate Client Ephemeral Key
     */
    generateClientEphemeralKey(): SRPKeyPair {
        const secretKey = randomBytes(this._engine.Nbytes);
        const publicKey = this._engine.computeA(BigInt.fromBuffer(secretKey)).toBuffer();
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
        const publicKey = this._engine.computeB(BigInt.fromBuffer(secretKey), BigInt.fromBuffer((verifier))).toBuffer();
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

        const a = BigInt.fromBuffer(key.secretKey);
        const A = BigInt.fromBuffer(key.publicKey);
        const B = BigInt.fromBuffer(serverPublicKey);
        const x = BigInt.fromBuffer(privateKey);

        // As in design: http://srp.stanford.edu/design.html
        if (B.mod(this._engine.N).eq(BigInt.ZERO)) {
            return null;
        }

        // 1. Random scrambling parameter
        const u = this._engine.computeU(A, B);
        // As in design: http://srp.stanford.edu/design.html
        if (u.mod(this._engine.N).eq(BigInt.ZERO)) {
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
            sessionKey: S.toBuffer(),
            clientProof: M.toBuffer(),
            serverProof: M2.toBuffer()
        };
    }

    computeServerSession(key: SRPKeyPair, clientPublicKey: Buffer, username: string, verifier: Buffer, salt: Buffer): SRPSession | null {
        const b = BigInt.fromBuffer(key.secretKey);
        const B = BigInt.fromBuffer(key.publicKey);
        const A = BigInt.fromBuffer(clientPublicKey);
        const v = BigInt.fromBuffer(verifier);

        // As in design: http://srp.stanford.edu/design.html
        if (A.mod(this._engine.N).eq(BigInt.ZERO)) {
            return null;
        }

        // 1. Random scrambling parameter
        const u = this._engine.computeU(A, B);
        // As in design: http://srp.stanford.edu/design.html
        if (u.mod(this._engine.N).eq(BigInt.ZERO)) {
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
            sessionKey: S.toBuffer(),
            clientProof: M.toBuffer(),
            serverProof: M2.toBuffer()
        };
    }
}