import bigInt, { BigInteger } from 'big-integer';

export function bigIntToBuffer(v: BigInteger) {
    return Buffer.from(v.toArray(256).value);
}

export function bufferToBigInt(v: Buffer) {
    return bigInt.fromArray([...v], 256, false);
}

export function padLeft(src: Buffer, length: number) {
    var padding = length - src.length;
    if (padding < 0) {
        throw Error('Invalid padding');
    }
    var result = Buffer.alloc(length);
    result.fill(0, 0, padding);
    src.copy(result, padding);
    return result;
}

export function bufferFromSpecHex(src: string) {
    return Buffer.from(src.replace(/\s/g, ''), 'hex')
}

export function sanitizeHex(src: string) {
    return src.replace(/\s/g, '');
}