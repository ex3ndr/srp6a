import crypto from 'crypto';
import { bufferFromSpecHex, sanitizeHex, bufferToBigInt, bigIntToBuffer } from './convert';
import { DefaultParams } from './DefaultParameters';
import { SRPEngine } from './SRPEngine';
import srpVectors from './_test_data/srptools.json';

describe('SRPEngine', () => {

    // Create Default Engine
    let engine: SRPEngine;
    beforeAll(() => {
        engine = SRPEngine.create(
            DefaultParams.rfc5054_1024.N,
            DefaultParams.rfc5054_1024.g,
            'sha-1'
        );
    });

    it('should compute multiplier', () => {
        expect(engine.k.toString(16).toUpperCase()).toBe('7556AA045AEF2CDD07ABAF0F665C3E818913186F');
    });

    it('should compute private key', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        const salt = bufferFromSpecHex('BEB25379D1A8581EB5A727673A2441EE');
        const expectedX = '94B7555AABE9127CC58CCF4993DB6CF84D16C124';
        const x = engine.computeX('alice', 'password123', salt);
        expect(x.toString(16).toUpperCase()).toBe(expectedX);
    });

    it('should compute verifier', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        const salt = bufferFromSpecHex('BEB25379D1A8581EB5A727673A2441EE');
        const expectedV =
            '7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812' +
            '9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5' +
            'C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5' +
            'EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78' +
            'E955A5E2 9E7AB245 DB2BE315 E2099AFB';

        const x = engine.computeX('alice', 'password123', salt);
        const v = engine.computeV(x);
        expect(v.toString(16).toUpperCase()).toBe(sanitizeHex(expectedV));
    });

    it('should compute server public key', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        const expectedB =
            'BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011' +
            'BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99' +
            '6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA' +
            '37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE' +
            'EB4012B7 D7665238 A8E3FB00 4B117B58';
        const v = bufferToBigInt(bufferFromSpecHex(
            '7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812' +
            '9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5' +
            'C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5' +
            'EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78' +
            'E955A5E2 9E7AB245 DB2BE315 E2099AFB'));
        const b = bufferToBigInt(bufferFromSpecHex(
            'E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1' +
            '05284D20'
        ));
        const B = engine.computeB(b, v);
        expect(B.toString(16).toUpperCase()).toBe(sanitizeHex(expectedB));
    });

    it('should compute server private key', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        const expectedA =
            '61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4' +
            '4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC' +
            '8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44' +
            'BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA' +
            'B349EF5D 76988A36 72FAC47B 0769447B';
        const a = bufferToBigInt(bufferFromSpecHex(
            '60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD' +
            'DA2D4393'
        ));
        const A = engine.computeA(a);
        expect(A.toString(16).toUpperCase()).toBe(sanitizeHex(expectedA));
    });

    it('should compute random scrambling parameter', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        const expectedU =
            'CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019';
        const A = bufferToBigInt(bufferFromSpecHex(
            '61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4' +
            '4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC' +
            '8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44' +
            'BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA' +
            'B349EF5D 76988A36 72FAC47B 0769447B'
        ));
        const B = bufferToBigInt(bufferFromSpecHex(
            'BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011' +
            'BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99' +
            '6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA' +
            '37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE' +
            'EB4012B7 D7665238 A8E3FB00 4B117B58'
        ));
        const u = engine.computeU(A, B);
        expect(u.toString(16).toUpperCase()).toBe(sanitizeHex(expectedU));
    });

    it('should compute client session key', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        // HINT: RFC use term premaster key while official design 
        // document (http://srp.stanford.edu/design.html) uses term
        // session key. We are naming session key is a key before hashing.
        const expectedS =
            'B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D' +
            '233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C' +
            '41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F' +
            '3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D' +
            'C346D7E4 74B29EDE 8A469FFE CA686E5A';
        const a = bufferToBigInt(bufferFromSpecHex(
            '60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD' +
            'DA2D4393'
        ));
        const B = bufferToBigInt(bufferFromSpecHex(
            'BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011' +
            'BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99' +
            '6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA' +
            '37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE' +
            'EB4012B7 D7665238 A8E3FB00 4B117B58'
        ));
        const x = bufferToBigInt(bufferFromSpecHex(
            '94B7555AABE9127CC58CCF4993DB6CF84D16C124'
        ));
        const u = bufferToBigInt(bufferFromSpecHex(
            'CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019'
        ));
        let S = engine.computeClientS(a, B, x, u);
        expect(S.toString(16).toUpperCase()).toBe(sanitizeHex(expectedS));
    });

    it('should compute server session key', () => {
        // Source: https://tools.ietf.org/html/rfc5054#appendix-A
        // HINT: RFC use term premaster key while official design 
        // document (http://srp.stanford.edu/design.html) uses term
        // session key. We are naming session key is a key before hashing.
        const expectedS =
            'B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D' +
            '233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C' +
            '41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F' +
            '3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D' +
            'C346D7E4 74B29EDE 8A469FFE CA686E5A';
        const b = bufferToBigInt(bufferFromSpecHex(
            'E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1' +
            '05284D20'
        ));
        const A = bufferToBigInt(bufferFromSpecHex(
            '61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4' +
            '4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC' +
            '8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44' +
            'BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA' +
            'B349EF5D 76988A36 72FAC47B 0769447B'
        ));
        const v = bufferToBigInt(bufferFromSpecHex(
            '7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812' +
            '9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5' +
            'C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5' +
            'EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78' +
            'E955A5E2 9E7AB245 DB2BE315 E2099AFB'
        ));
        const u = bufferToBigInt(bufferFromSpecHex(
            'CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019'
        ));

        let S = engine.computeServerS(b, A, v, u);
        expect(S.toString(16).toUpperCase()).toBe(sanitizeHex(expectedS));
    });

    it('should compute server strong session key', () => {
        // NOTE that this value is not part of the RFC 5054 test vectors.
        // We calculated it by simply hashing raw premaster key with SHA-1
        const expectedK = '17eefa1cefc5c2e626e21598987f31e0f1b11bb';
        const S = bufferToBigInt(bufferFromSpecHex('B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D' +
            '233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C' +
            '41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F' +
            '3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D' +
            'C346D7E4 74B29EDE 8A469FFE CA686E5A'));
        let K = engine.computeK(S);
        expect(K.toString(16)).toBe(expectedK);
    });

    it('should pass test vectors', () => {
        for (let vector of srpVectors.testVectors) {
            if (vector.H !== 'sha1' && vector.H !== 'sha256' && vector.H !== 'sha512') {
                continue;
            }
            const testEngine = SRPEngine.create(
                vector.N,
                vector.g,
                vector.H === 'sha1' ? 'sha-1' : (vector.H === 'sha256' ? 'sha-256' : 'sha-512')
            );

            // Test Key Size
            expect(testEngine.Nbits).toBe(vector.size);

            // Test k - Multiplier
            expect(bigIntToBuffer(testEngine.k).toString('hex')).toBe(vector.k);

            // Prepare
            const I = vector.I;
            const p = vector.P;
            const s = bufferFromSpecHex(vector.s);

            // Private Key
            const x = testEngine.computeX(I, p, s);
            expect(bigIntToBuffer(x).toString('hex')).toBe(vector.x);

            // Verifier
            const v = testEngine.computeV(x);
            expect(bigIntToBuffer(v).toString('hex')).toBe(vector.v);

            // Client Public Key
            const a = bufferToBigInt(bufferFromSpecHex(vector.a));
            const A = testEngine.computeA(a);
            expect(bigIntToBuffer(A).toString('hex')).toBe(vector.A);

            // Server Public Key
            const b = bufferToBigInt(bufferFromSpecHex(vector.b));
            const B = testEngine.computeB(b, v);
            expect(bigIntToBuffer(B).toString('hex')).toBe(vector.B);

            // Random Scrubling Parameter
            const u = testEngine.computeU(A, B);
            expect(bigIntToBuffer(u).toString('hex')).toBe(vector.u);

            // Client Session Key
            const S = testEngine.computeClientS(a, B, x, u);
            expect(bigIntToBuffer(S).toString('hex')).toBe(vector.S);

            // Server Session Key
            const SS = testEngine.computeServerS(b, A, v, u);
            expect(bigIntToBuffer(SS).toString('hex')).toBe(vector.S);

            // Server Session Strong Key
            const K = testEngine.computeK(S);
            expect(bigIntToBuffer(K).toString('hex')).toBe(vector.K);

            // Client Proof
            const M1 = testEngine.computeClientProof(I, s, A, B, K);
            expect(bigIntToBuffer(M1).toString('hex')).toBe(vector.M1);

            // Server Proof
            const M2 = testEngine.computeServerProof(A, M1, K);
            expect(bigIntToBuffer(M2).toString('hex')).toBe(vector.M2);
        }
    });
});