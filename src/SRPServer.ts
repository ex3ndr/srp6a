import { SRPParams } from "./SRPParams";
import { SRP, SRPKeyPair } from "./SRP";
import { constantTimeEq } from "./utils/constantTimeEq";

export class SRPServer {
    private readonly _srp: SRP;

    // Credentials
    private _username!: string;
    private _verifier!: Uint8Array;
    private _salt!: Uint8Array;

    // Keys
    private _ephemeralKey!: SRPKeyPair;
    private _clientKey!: Uint8Array;

    // Session
    private _proof!: Uint8Array;
    private _clientProof!: Uint8Array;
    private _sessionKey!: Uint8Array;

    private _state: 'm0' | 'm1' | 'm2' | 'success' | 'failure' = 'm0';

    constructor(params: SRPParams) {
        this._srp = new SRP(params);
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

    setCredentials(username: string, verifier: Uint8Array, salt: Uint8Array): boolean {
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

    setClientKey(publicKey: Uint8Array): boolean {
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

    validateProof(proof: Uint8Array): boolean {
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