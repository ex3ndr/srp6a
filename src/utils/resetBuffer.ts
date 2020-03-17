export function resetBuffer(src: Uint8Array) {
    for (let i = 0; i < src.length; i++) {
        src[i] = Math.floor(Math.random() * 256);
    }
}