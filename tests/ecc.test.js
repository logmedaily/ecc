const crypto = require('crypto');
const {generateMnemonic, mnemonicToSeed, validateBIP39Mnemonic} = require('@logmedaily/bip39');
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
    convertSharedExchangeKeyToBuffer, deriveDomainSeed, generateRandomSeed, getIdentityPublicKeyHex,
    verifyIdentityAddress
} = require('../lib');

describe('Cryptographic Function Tests', () => {

    const mnemonic = generateMnemonic(12);
    console.log(`generated mnemonic logged for testing - ${mnemonic}`);

    const isMnemonicValid = validateBIP39Mnemonic(mnemonic);
    console.log(`is generated mnemonic valid ${isMnemonicValid}`);

    const baseSeed = mnemonicToSeed(mnemonic, 'example pass phrase');

    console.log(`generatedSeed is ${baseSeed.toString('hex')}`);

    const seeds = {
        network: deriveDomainSeed(baseSeed, 'network'),
        identity: deriveDomainSeed(baseSeed, 'identity'),
        data: deriveDomainSeed(baseSeed, 'data'),
    };

    const keyPairs = {
        network: seedToKeyPair(seeds.network),
        identity: seedToKeyPair(seeds.identity),
        data: seedToKeyPair(seeds.data),
    };
    const keyPair = seedToKeyPair(baseSeed);

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

    describe('Shared Exchange Key Tests', () => {
        const recipientMnemonic = generateMnemonic(15);
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = mnemonicToSeed(recipientMnemonic, 'recipient pass phrase');
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
        const recipientMnemonic = generateMnemonic(15);
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = mnemonicToSeed(recipientMnemonic, 'recipient pass phrase');
        const recipientKeyPair = seedToKeyPair(recipientSeed);

        const sharedExchangeKeyBN = generateSharedExchangeKey(keyPair, recipientKeyPair.getPublic());

        const sharedExchangeKeyBuffer = convertSharedExchangeKeyToBuffer(sharedExchangeKeyBN);

        const message = "Secret message";

        const encryptedMessage = encryptWithSharedExchangeKey(message, sharedExchangeKeyBuffer);

        const decryptedMessage = decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKeyBuffer);
        console.log(encryptedMessage, message, decryptedMessage);
        expect(decryptedMessage).toBe(message);
    });

    test('Unique seeds across domains', () => {
        const networkSeedHex = seeds.network.toString('hex');
        const identitySeedHex = seeds.identity.toString('hex');
        const dataSeedHex = seeds.data.toString('hex');

        expect(networkSeedHex).not.toBe(identitySeedHex);
        expect(networkSeedHex).not.toBe(dataSeedHex);
        expect(identitySeedHex).not.toBe(dataSeedHex);
    });

    test('Deterministic key pair regeneration', () => {
        const regeneratedKeyPair = seedToKeyPair(baseSeed);

        expect(getPublicKeyHex(keyPair)).toBe(getPublicKeyHex(regeneratedKeyPair));
        expect(getPrivateKeyHex(keyPair)).toBe(getPrivateKeyHex(regeneratedKeyPair));
    });

    test('Handle minimum seed length gracefully', () => {
        expect(() => {
            seedToKeyPair(Buffer.from('short'));
        }).toThrow('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
    });

    test('Handle minimum seed length gracefully', () => {
        const shortSeed = Buffer.from('1234567890123456');
        expect(() => seedToKeyPair(shortSeed)).toThrow('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
    });


    test('Graceful handling of decryption with incorrect key', () => {
        const wrongKey = crypto.randomBytes(32);
        const recipientMnemonic = generateMnemonic(15);
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = mnemonicToSeed(recipientMnemonic, 'recipient pass phrase');
        const recipientKeyPair = seedToKeyPair(recipientSeed);
        const sharedExchangeKey = generateSharedExchangeKey(keyPair, getPublicKey(recipientKeyPair));
        const sharedExchangeKeyBuffer = convertSharedExchangeKeyToBuffer(sharedExchangeKey);
        const encryptedMessage = encryptWithSharedExchangeKey("Test message", sharedExchangeKeyBuffer);
        expect(() => {
            decryptWithSharedExchangeKey(encryptedMessage, wrongKey);
        }).toThrow();
    });

    test('Signing with timestamp and nonce', () => {
        const message = "Test Message!";
        const { signature, nonce, timestamp } = sign(message, keyPair);

        expect(signature).toBeDefined();
        expect(nonce).toMatch(/^[0-9a-fA-F]+$/);
        expect(timestamp).toBeLessThanOrEqual(Date.now());

        console.log(`Signed at ${new Date(timestamp).toISOString()} with nonce ${nonce}: ${signature}`);
    });

    test('Verifying with timestamp and nonce within validity period', done => {
        const message = "Test Message!";
        const { signature, nonce, timestamp } = sign(message, keyPair);

        setTimeout(() => {
            const isVerified = verify(message, signature, nonce, timestamp, keyPair);
            expect(isVerified).toBe(true);
            done();
        }, 1000);
    }, 2000);


    test('Ensuring nonce uniqueness in consecutive signatures', () => {
        const message = "Test Message!";
        const firstSignatureData = sign(message, keyPair);
        const secondSignatureData = sign(message, keyPair);
        expect(firstSignatureData.nonce).not.toEqual(secondSignatureData.nonce);
    });

    test('Domain-specific seeds are distinct', () => {
        const networkSeed = deriveDomainSeed(baseSeed, 'network').toString('hex');
        const identitySeed = deriveDomainSeed(baseSeed, 'identity').toString('hex');
        const dataSeed = deriveDomainSeed(baseSeed, 'data').toString('hex');

        expect(networkSeed).not.toBe(identitySeed);
        expect(networkSeed).not.toBe(dataSeed);
        expect(identitySeed).not.toBe(dataSeed);
    });

    test('Ephemeral keys are unique for each session', () => {
        const ephemeralKeyPair1 = seedToKeyPair(generateRandomSeed(), 'ephemeral');
        const ephemeralKeyPair2 = seedToKeyPair(generateRandomSeed(), 'ephemeral');

        expect(getPublicKeyHex(ephemeralKeyPair1)).not.toBe(getPublicKeyHex(ephemeralKeyPair2));
    });

    test('Checksum validation detects errors in identity addresses', () => {
        const attribute = "example";
        const identityAddress = getIdentityPublicKeyHex(attribute, keyPairs.identity);

        console.log(`Identity Address: ${identityAddress}`);

        const alteredAddress = identityAddress.substring(0, identityAddress.length - 1) + (identityAddress[identityAddress.length - 1] === '1' ? '0' : '1');
        console.log(`Altered Address: ${alteredAddress}`);

        const isValid = verifyIdentityAddress(alteredAddress, attribute, keyPairs.identity);
        expect(isValid).toBeFalsy();
    });

    test('Regeneration of domain-specific keys is consistent', () => {
        const seed = generateRandomSeed();
        const domain = 'network';

        const keyPair1 = seedToKeyPair(seed, domain);
        const keyPair2 = seedToKeyPair(seed, domain);

        expect(getPublicKeyHex(keyPair1)).toBe(getPublicKeyHex(keyPair2));
    });



});
