import { SRPParams } from './SRPParams';
import { SRP, SRPKeyPair } from './SRP';
import { constantTimeEq } from './utils/constantTimeEq';
import { resetBuffer } from './utils/resetBuffer';

export class SRPClient {
    private readonly _srp: SRP;

    // Credentials
    private _username!: string;
    private _privateKey!: Buffer;
    private _salt!: Buffer;

    // Ephemeral keys
    private _ephemeralKey!: SRPKeyPair;
    private _serverKey!: Buffer;

    // Session
    private _proof!: Buffer;
    private _serverProof!: Buffer;
    private _sessionKey!: Buffer;

    // State
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
        if (!this._proof) {
            throw Error('Server key not set!');
        }
        return this._proof;
    }

    get sessionKey() {
        if (this._state !== 'success') {
            throw Error('Client not in success state');
        }
        return this._sessionKey;
    }

    setCredentials(username: string, password: string, salt: Buffer): boolean {
        if (this._state !== 'm0') {
            throw Error('Invalid state. Expected: m0, got: ' + this._state);
        }
        this._username = username;
        this._salt = salt;
        this._privateKey = this._srp.computePrivateKey(username, password, salt);
        this._ephemeralKey = this._srp.generateClientEphemeralKey();
        this._state = 'm1';
        return true;
    }

    setServerKey(publicKey: Buffer): boolean {
        if (this._state !== 'm1') {
            throw Error('Invalid state. Expected: m1, got: ' + this._state);
        }
        this._serverKey = publicKey;
        let clientSession = this._srp.computeClientSession(
            this._ephemeralKey,
            this._serverKey,
            this._username,
            this._salt,
            this._privateKey
        );
        if (!clientSession) {
            this._state = 'failure';
            this.cleanup();
            return false;
        }
        this._proof = clientSession.clientProof;
        this._sessionKey = clientSession.sessionKey;
        this._serverProof = clientSession.serverProof;
        this._state = 'm2';
        return true;
    }

    validateProof(proof: Buffer): boolean {
        if (this._state !== 'm2') {
            throw Error('Invalid state. Expected: m1, got: ' + this._state);
        }
        if (constantTimeEq(proof, this._serverProof)) {
            this._state = 'success';
            this.cleanup();
            return true;
        } else {
            this._state = 'failure';
            this.cleanup();
            return false;
        }
    }

    private cleanup() {
        // Discard private key immediatelly
        if (this._privateKey) {
            resetBuffer(this._privateKey);
        }
    }
}