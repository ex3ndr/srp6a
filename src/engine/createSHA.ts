import { Hash } from 'crypto';
import sha from 'sha.js';
import { Hash as SRPHash } from "./SRPEngine";

export function createSHA(type: 'sha-1' | 'sha-256' | 'sha-512'): SRPHash {
    return (...src) => {
        let dgst: Hash;
        if (type === 'sha-512') {
            dgst = sha('sha512');
        } else if (type === 'sha-256') {
            dgst = sha('sha256');
        } else if (type === 'sha-1') {
            dgst = sha('sha1');
        } else {
            throw Error('Invalid hash');
        }

        for (let s of src) {
            dgst.update(s);
        }

        return dgst.digest();
    };
}