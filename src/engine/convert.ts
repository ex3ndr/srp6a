import bigInt, { BigInteger } from 'big-integer';
import * as hex from '@stablelib/hex';
import * as utf8 from '@stablelib/utf8';

export function bigIntToArray(v: BigInteger): Uint8Array {
    return Uint8Array.from(v.toArray(256).value);
}

export function arrayToBigInt(v: Uint8Array) {
    return bigInt.fromArray([...v], 256, false);
}

export function padLeft(src: Uint8Array, length: number) {
    var padding = length - src.length;
    if (padding < 0) {
        throw Error('Invalid padding');
    }
    var result = new Uint8Array(length);
    result.fill(0, 0, padding);
    result.set(src, padding);
    return result;
}

export function stringToArray(src: string) {
    return utf8.encode(src);
}

export function arrayFromSpecHex(src: string): Uint8Array {
    return hex.decode(src.replace(/\s/g, ''))
}

export function arrayToHex(src: Uint8Array) {
    return hex.encode(src);
}

export function sanitizeHex(src: string) {
    return src.replace(/\s/g, '');
}