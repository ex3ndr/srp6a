export function resetBuffer(src: Buffer) {
    for (let i = 0; i < src.length; i++) {
        src[i] = Math.floor(Math.random() * 256);
    }
}