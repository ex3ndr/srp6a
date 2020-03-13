import { SRPServer } from './SRPServer';
import { SRPClient } from './SRPClient';
import crypto from 'crypto';
import { SRP } from './SRP';

describe('SRP', () => {
    it('should perform successful negotiation', () => {
        const srp = new SRP('default', crypto.randomBytes);
        const client = new SRPClient('default', crypto.randomBytes);
        const server = new SRPServer('default', crypto.randomBytes);

        const username = 'randomKing';
        const password = 'pas$$word';
        const salt = srp.generateSalt();
        const verifier = srp.computeVerifier(username, password, salt);

        // Set credentials
        expect(client.setCredentials(username, password, salt)).toBe(true);
        expect(server.setCredentials(username, verifier, salt)).toBe(true);

        // Exchange keys
        expect(server.setClientKey(client.publicKey)).toBe(true);
        expect(client.setServerKey(server.publicKey)).toBe(true);

        // Validate proofs
        expect(server.validateProof(client.proof)).toBe(true);
        expect(client.validateProof(server.proof)).toBe(true);

        // Check session keys
        expect(server.sessionKey.toString('hex')).toBe(client.sessionKey.toString('hex'));
    });
});