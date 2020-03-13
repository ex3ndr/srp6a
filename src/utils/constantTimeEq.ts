export function constantTimeEq(a: Buffer, b: Buffer) {
    if (a.length !== b.length) {
        return false;
    }

    var c = 0;
    for (var i = 0; i < a.length; i++) {
        c |= a[i] ^ b[i];
    }
    return c === 0;
}