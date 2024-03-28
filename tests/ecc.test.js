const crypto = require('crypto');
const {
    seedToKeyPair,
    getPublicKey,
    getPrivateKey,
    getPublicKeyHex,
    getPrivateKeyHex,
    sign,
    verify,
    generateSharedExchangeKey,
    encryptWithSharedExchangeKey,
    decryptWithSharedExchangeKey, generateSharedExchangeKeyHex, generateSharedExchangeKeyBN,
    convertSharedExchangeKeyToBuffer
} = require('../lib');

describe('Cryptographic Function Tests', () => {
    const seed = crypto.randomBytes(32);
    const keyPair = seedToKeyPair(seed);

    test('Key pair generation from seed', () => {
        expect(keyPair).toBeDefined();
        expect(keyPair.getPrivate()).toBeDefined();
        expect(keyPair.getPublic()).toBeDefined();
    });

    test('Public and private key retrieval', () => {
        const publicKey = getPublicKey(keyPair);
        const privateKey = getPrivateKey(keyPair);
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
    });

    test('Hex conversion for public and private keys', () => {
        const publicKeyHex = getPublicKeyHex(keyPair);
        const privateKeyHex = getPrivateKeyHex(keyPair);
        expect(publicKeyHex).toMatch(/^[0-9a-fA-F]+$/);
        expect(privateKeyHex).toMatch(/^[0-9a-fA-F]+$/);
    });

    test('Signing and verifying a message', () => {
        const message = "Hello, world!";
        const signature = sign(message, keyPair);
        const isVerified = verify(message, signature, keyPair);
        expect(isVerified).toBe(true);
    });
    describe('Shared Exchange Key Tests', () => {
        const recipientSeed = crypto.randomBytes(32);
        const recipientKeyPair = seedToKeyPair(recipientSeed);
        const sharedKey = generateSharedExchangeKey(keyPair, recipientKeyPair.getPublic());

        test('generateSharedExchangeKeyBN returns a base 16 string', () => {
            const sharedKeyBase16 = generateSharedExchangeKeyBN(keyPair, recipientKeyPair.getPublic());
            expect(sharedKeyBase16).toMatch(/^[0-9a-fA-F]+$/);
        });

        test('generateSharedExchangeKeyHex returns a hex string', () => {
            const sharedKeyHex = generateSharedExchangeKeyHex(keyPair, recipientKeyPair.getPublic());
            expect(sharedKeyHex).toMatch(/^[0-9a-fA-F]+$/);
        });

        test('generateSharedExchangeKey returns a shared key with expected properties', () => {
            expect(typeof sharedKey.toString).toBe('function');
        });

        test('convertSharedExchangeKeyToBuffer converts shared key to Buffer', () => {
            const sharedKeyBuffer = convertSharedExchangeKeyToBuffer(sharedKey);
            expect(sharedKeyBuffer).toBeInstanceOf(Buffer);
        });
    });


    test('Encryption and decryption with shared exchange key', () => {
        const recipientSeed = crypto.randomBytes(32);
        const recipientKeyPair = seedToKeyPair(recipientSeed);

        const sharedExchangeKeyBN = generateSharedExchangeKey(keyPair, recipientKeyPair.getPublic());

        const sharedExchangeKeyBuffer = convertSharedExchangeKeyToBuffer(sharedExchangeKeyBN);

        const message = "Secret message";

        const encryptedMessage = encryptWithSharedExchangeKey(message, sharedExchangeKeyBuffer);

        const decryptedMessage = decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKeyBuffer);
        console.log(encryptedMessage, message, decryptedMessage);
        expect(decryptedMessage).toBe(message);
    });

});
