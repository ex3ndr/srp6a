import { BigInteger } from 'jsbn';

const kBigInteger = Symbol('big-integer');

export class BigInt {


    static fromBuffer(buffer: Buffer) {
        return new BigInt(new BigInteger(buffer.toString('hex'), 16));
    }

    static ZERO = BigInt.fromBuffer(Buffer.from([]));

    private [kBigInteger]: BigInteger;

    constructor(raw: BigInteger) {
        this[kBigInteger] = raw;
    }

    eq(val: BigInt) {
        return this[kBigInteger].equals(val[kBigInteger])
    }

    add(bigInt: BigInt): BigInt {
        return new BigInt(this[kBigInteger].add(bigInt[kBigInteger]));
    }

    subtract(bigInt: BigInt): BigInt {
        return new BigInt(this[kBigInteger].subtract(bigInt[kBigInteger]));
    }

    multiply(bigInt: BigInt): BigInt {
        return new BigInt(this[kBigInteger].multiply(bigInt[kBigInteger]));
    }

    mod(v: BigInt): BigInt {
        return new BigInt(this[kBigInteger].mod(v[kBigInteger]));
    }

    modPow(e: BigInt, n: BigInt): BigInt {
        return new BigInt(this[kBigInteger].modPow(e[kBigInteger], n[kBigInteger]));
    }

    xor(bigInt: BigInt): BigInt {
        return new BigInt(this[kBigInteger].xor(bigInt[kBigInteger]));
    }

    toHex() {
        let res = this[kBigInteger].toString(16);
        if (res.length % 2 === 1) {
            return '0' + res;
        } else {
            return res;
        }
    }

    toBuffer() {
        return Buffer.from(this.toHex(), 'hex');
    }
}