import { SRPParams } from "./SRPParams";
import { PRNG, SRP, SRPKeyPair } from "./SRP";
import { constantTimeEq } from "./utils/constantTimeEq";

export class SRPServer {
    private readonly _srp: SRP;

    // Credentials
    private _username!: string;
    private _verifier!: Buffer;
    private _salt!: Buffer;

    // Keys
    private _ephemeralKey!: SRPKeyPair;
    private _clientKey!: Buffer;

    // Session
    private _proof!: Buffer;
    private _clientProof!: Buffer;
    private _sessionKey!: Buffer;

    private _state: 'm0' | 'm1' | 'm2' | 'success' | 'failure' = 'm0';

    constructor(params: SRPParams, prng: PRNG) {
        this._srp = new SRP(params, prng);
    }

    get state() {
        return this._state;
    }

    get publicKey() {
        if (!this._ephemeralKey) {
            throw Error('Credentials not set!');
        }
        return this._ephemeralKey.publicKey;
    }

    get proof() {
        if (this._state !== 'success') {
            throw Error('You can\'t read proof until you verified client one');
        }
        return this._proof;
    }

    get sessionKey() {
        if (this._state !== 'success') {
            throw Error('Server not in success state');
        }
        return this._sessionKey;
    }

    setCredentials(username: string, verifier: Buffer, salt: Buffer): boolean {
        if (this._state !== 'm0') {
            throw Error('Invalid state. Expected: m0, got: ' + this._state);
        }
        this._username = username;
        this._verifier = verifier;
        this._salt = salt;
        this._ephemeralKey = this._srp.generateServerEphemeralKey(verifier);
        this._state = 'm1';
        return true;
    }

    setClientKey(publicKey: Buffer): boolean {
        if (this._state !== 'm1') {
            throw Error('Invalid state. Expected: m1, got: ' + this._state);
        }
        this._clientKey = publicKey;
        let session = this._srp.computeServerSession(
            this._ephemeralKey,
            this._clientKey,
            this._username,
            this._verifier,
            this._salt
        );
        if (!session) {
            this._state = 'failure';
            return false;
        }

        this._proof = session.serverProof;
        this._sessionKey = session.sessionKey;
        this._clientProof = session.clientProof;
        this._state = 'm2';
        return true;
    }

    validateProof(proof: Buffer): boolean {
        if (this._state !== 'm2') {
            throw Error('Invalid state. Expected: m2, got: ' + this._state);
        }
        if (constantTimeEq(proof, this._clientProof)) {
            this._state = 'success';
            return true;
        } else {
            this._state = 'failure';
            return false;
        }
    }
}