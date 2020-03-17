import bigint, { BigInteger } from 'big-integer';
import { arrayToBigInt, arrayFromSpecHex, padLeft, bigIntToArray, stringToArray } from './convert';
import { createSHA } from './createSHA';

/**
 * Hash function interface
 */
export type Hash = (...src: (Uint8Array)[]) => Uint8Array;

/**
 * Low Level SRP Engine that implements all required math for 
 * SRP implementation
 */
export class SRPEngine {

    static create(N: string, g: string, H: 'sha-1' | 'sha-256' | 'sha-512' | Hash) {
        const bN = arrayFromSpecHex(N);
        const bg = arrayFromSpecHex(g);
        let h: Hash;
        if (typeof H === 'string') {
            h = createSHA(H);
        } else {
            h = H;
        }
        const k = arrayToBigInt(h(bN, padLeft(bg, bN.length)));
        return new SRPEngine(
            arrayToBigInt(bN),
            arrayToBigInt(bg),
            k,
            h
        );
    }

    readonly N: BigInteger;
    readonly Nbits: number;
    readonly Nbytes: number;
    readonly g: BigInteger;
    readonly k: BigInteger;
    readonly H: Hash;

    constructor(
        N: BigInteger,
        g: BigInteger,
        k: BigInteger,
        H: Hash
    ) {
        this.N = N;
        this.Nbits = N.bitLength().toJSNumber();
        this.Nbytes = Math.ceil(this.Nbits / 8);
        this.g = g;
        this.k = k;
        this.H = H;
        Object.freeze(this);
    }

    /**
     * Computing x - Private key
     * @param I User Identity
     * @param p User Password
     * @param s User Salt
     */
    computeX(I: string, p: string, s: Uint8Array): BigInteger {
        const H = this._H;

        // x = H(s, H(I | ':' | p))  (s is chosen randomly)
        let x = H(s, H(I, ':', p));

        return x;
    }

    /**
     * Computing v - Verifier
     * @param x Private Key
     */
    computeV(x: BigInteger): BigInteger {
        const N = this.N;
        const g = this.g;

        // v = g^x
        return g.modPow(x, N);
    }

    /**
     * Compute B - server public key
     * @param v verifier
     * @param b secret key
     */
    computeB(b: BigInteger, v: BigInteger): BigInteger {
        const N = this.N;
        const g = this.g;
        const k = this.k;

        // B = kv + g^b             (b = random number)
        return k.multiply(v).mod(N).add(g.modPow(b, N)).mod(N);
    }

    /**
     * Compute A - client public key
     * @param a secret key
     */
    computeA(a: BigInteger): BigInteger {
        const N = this.N;
        const g = this.g;

        // A = g^a                  (a = random number)
        return g.modPow(a, N);
    }

    /**
     * Compute u - Random scrambling parameter
     * @param A Client public key
     * @param B Server public key
     */
    computeU(A: BigInteger, B: BigInteger): BigInteger {
        const N = this.N;
        const H = this._H;

        // u = H(A, B)
        return H(A, B).mod(N);
    }

    /**
     * Compute Client S - Session Key
     * @param a Client secret key
     * @param B Server public key
     * @param x Private key
     * @param u Random Scrambling Parameter
     */
    computeClientS(a: BigInteger, B: BigInteger, x: BigInteger, u: BigInteger) {

        const N = this.N;
        const g = this.g;
        const k = this.k;

        //
        // We need to make kg^x calculated by modulo sicne it otherwise overflow
        // and subscription will be negative and mod operation will result
        // in incorrect values.
        // Also we adding N to B before subsctraction.
        // 

        // S = (B - kg^x) ^ (a + ux) 
        return B.add(N).subtract(k.multiply(g.modPow(x, N)).mod(N)).mod(N).modPow(a.add(u.multiply(x)), N);
    }

    /**
     * Compute Server S - Session key
     * @param b Server secret key
     * @param A Client public key
     * @param v Verifier
     * @param u Random Scrambling Parameter
     */
    computeServerS(b: BigInteger, A: BigInteger, v: BigInteger, u: BigInteger) {
        const N = this.N;

        // S = (Av^u) ^ b
        return A.multiply(v.modPow(u, N)).modPow(b, N);
    }

    /**
     * Compute K - Strong Session Key
     * @param S Session key
     */
    computeK = (S: BigInteger) => {
        return this._H(S);
    }

    /**
     * Compute Client Proof
     * @param I User Identity
     * @param s User Salt
     * @param A Client public key
     * @param B Server public key
     * @param K Strong Session Key
     */
    computeClientProof = (I: string, s: Uint8Array, A: BigInteger, B: BigInteger, K: BigInteger) => {
        const H = this._H;
        const N = this.N;
        const g = this.g;
        return H(H(N).xor(H(g)), H(I), s, A, B, K);
    }

    /** 
     * Compute Server Proof
     * @param A Client public key
     * @param M Client proof
     * @param K Strong Session Key
     */
    computeServerProof = (A: BigInteger, M: BigInteger, K: BigInteger) => {
        const H = this._H;
        return H(A, M, K);
    }

    /**
     * Hashing wrapper
     */
    private _H = (...src: (BigInteger | Uint8Array | string)[]) => {
        let mapped = src.map((i) => {
            if (typeof i === 'string') {
                return stringToArray(i);
            } else if (i instanceof Uint8Array) {
                return i;
            } else if (bigint.isInstance(i)) {
                return bigIntToArray(i);
            } else {
                throw Error('Invalid data');
            }
        })
        return arrayToBigInt(this.H(...mapped));
    }
}