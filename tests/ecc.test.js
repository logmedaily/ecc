const crypto = require('crypto');
const Bip39 = require('@logmedaily/bip39');
const Ecc = require('../lib');
const ecc = new Ecc('Yo');
const bip39 = new Bip39();

describe('Cryptographic Function Tests', () => {

    const mnemonic = bip39.generateMnemonic({numberOfWords: 12, });
    console.log(`generated mnemonic logged for testing - ${mnemonic}`);

    const isMnemonicValid = bip39.validateBIP39Mnemonic(mnemonic);
    console.log(`is generated mnemonic valid ${isMnemonicValid}`);

    const baseSeed = bip39.mnemonicToSeed({mnemonic: mnemonic, passphrase: 'example pass phrase'});

    console.log(`generatedSeed is ${baseSeed.toString('hex')}`);

    const seeds = {
        network: ecc.deriveDomainSeed(baseSeed, 'network'),
        identity: ecc.deriveDomainSeed(baseSeed, 'identity'),
        data: ecc.deriveDomainSeed(baseSeed, 'data'),
    };

    const keyPairs = {
        network: ecc.seedToKeyPair(seeds.network),
        identity: ecc.seedToKeyPair(seeds.identity),
        data: ecc.seedToKeyPair(seeds.data),
    };
    const keyPair = ecc.seedToKeyPair(baseSeed);

    test('Key pair generation from seed', () => {
        expect(keyPair).toBeDefined();
        expect(keyPair.getPrivate()).toBeDefined();
        expect(keyPair.getPublic()).toBeDefined();
    });

    test('Public and private key retrieval', () => {
        const publicKey = ecc.getPublicKey(keyPair);
        const privateKey = ecc.getPrivateKey(keyPair);
        expect(publicKey).toBeDefined();
        expect(privateKey).toBeDefined();
    });

    test('Hex conversion for public and private keys', () => {
        const publicKeyHex = ecc.getPublicKeyHex(keyPair);
        const privateKeyHex = ecc.getPrivateKeyHex(keyPair);
        expect(publicKeyHex).toMatch(/^[0-9a-fA-F]+$/);
        expect(privateKeyHex).toMatch(/^[0-9a-fA-F]+$/);
    });

    describe('Shared Exchange Key Tests', () => {
        const recipientMnemonic = bip39.generateMnemonic({numberOfWords: 12});
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = bip39.validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = bip39.mnemonicToSeed({mnemonic: recipientMnemonic, passphrase:'recipient pass phrase'});
        const recipientKeyPair = ecc.seedToKeyPair(recipientSeed);
        const sharedKey = ecc.generateSharedExchangeKey(keyPair, recipientKeyPair.getPublic());

        test('generateSharedExchangeKeyBN returns a base 16 string', () => {
            const sharedKeyBase16 = ecc.generateSharedExchangeKeyBN(keyPair, recipientKeyPair.getPublic());
            expect(sharedKeyBase16).toMatch(/^[0-9a-fA-F]+$/);
        });

        test('generateSharedExchangeKeyHex returns a hex string', () => {
            const sharedKeyHex = ecc.generateSharedExchangeKeyHex(keyPair, recipientKeyPair.getPublic());
            expect(sharedKeyHex).toMatch(/^[0-9a-fA-F]+$/);
        });

        test('generateSharedExchangeKey returns a shared key with expected properties', () => {
            expect(typeof sharedKey.toString).toBe('function');
        });

        test('convertSharedExchangeKeyToBuffer converts shared key to Buffer', () => {
            const sharedKeyBuffer = ecc.convertSharedExchangeKeyToBuffer(sharedKey);
            expect(sharedKeyBuffer).toBeInstanceOf(Buffer);
        });
    });


    test('Encryption and decryption with shared exchange key', () => {
        const recipientMnemonic = bip39.generateMnemonic({numberOfWords: 15});
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = bip39.validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = bip39.mnemonicToSeed({mnemonic: recipientMnemonic, passphrase:'recipient pass phrase'});
        const recipientKeyPair = ecc.seedToKeyPair(recipientSeed);

        const sharedExchangeKeyBN = ecc.generateSharedExchangeKey(keyPair, recipientKeyPair.getPublic());

        const sharedExchangeKeyBuffer = ecc.convertSharedExchangeKeyToBuffer(sharedExchangeKeyBN);

        const message = "Secret message";

        const encryptedMessage = ecc.encryptWithSharedExchangeKey(message, sharedExchangeKeyBuffer);

        const decryptedMessage = ecc.decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKeyBuffer);
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
        const regeneratedKeyPair = ecc.seedToKeyPair(baseSeed);

        expect(ecc.getPublicKeyHex(keyPair)).toBe(ecc.getPublicKeyHex(regeneratedKeyPair));
        expect(ecc.getPrivateKeyHex(keyPair)).toBe(ecc.getPrivateKeyHex(regeneratedKeyPair));
    });

    test('Handle minimum seed length gracefully', () => {
        expect(() => {
            ecc.seedToKeyPair(Buffer.from('short'));
        }).toThrow('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
    });

    test('Handle minimum seed length gracefully', () => {
        const shortSeed = Buffer.from('1234567890123456');
        expect(() => ecc.seedToKeyPair(shortSeed)).toThrow('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
    });


    test('Graceful handling of decryption with incorrect key', () => {
        const wrongKey = crypto.randomBytes(32);
        const recipientMnemonic = bip39.generateMnemonic({numberOfWords: 15});
        console.log(`generated recipientMnemonic logged for testing - ${recipientMnemonic}`);

        const isRecipientMnemonicValid = bip39.validateBIP39Mnemonic(recipientMnemonic);
        console.log(`is recipient generated mnemonic valid ${isRecipientMnemonicValid}`);

        const recipientSeed = bip39.mnemonicToSeed({mnemonic: recipientMnemonic, passphrase:'recipient pass phrase'});
        const recipientKeyPair = ecc.seedToKeyPair(recipientSeed);
        const sharedExchangeKey = ecc.generateSharedExchangeKey(keyPair, ecc.getPublicKey(recipientKeyPair));
        const sharedExchangeKeyBuffer = ecc.convertSharedExchangeKeyToBuffer(sharedExchangeKey);
        const encryptedMessage = ecc.encryptWithSharedExchangeKey("Test message", sharedExchangeKeyBuffer);
        expect(() => {
            ecc.decryptWithSharedExchangeKey(encryptedMessage, wrongKey);
        }).toThrow();
    });

    test('Signing with timestamp and nonce', () => {
        const message = "Test Message!";
        const { signature, nonce, timestamp } = ecc.sign(message, keyPair);

        expect(signature).toBeDefined();
        expect(nonce).toMatch(/^[0-9a-fA-F]+$/);
        expect(timestamp).toBeLessThanOrEqual(Date.now());

        console.log(`Signed at ${new Date(timestamp).toISOString()} with nonce ${nonce}: ${signature}`);
    });

    test('Verifying with timestamp and nonce within validity period', done => {
        const message = "Test Message!";
        const { signature, nonce, timestamp } = ecc.sign(message, keyPair);

        setTimeout(() => {
            const isVerified = ecc.verify(message, signature, nonce, timestamp, keyPair);
            expect(isVerified).toBe(true);
            done();
        }, 1000);
    }, 2000);


    test('Ensuring nonce uniqueness in consecutive signatures', () => {
        const message = "Test Message!";
        const firstSignatureData = ecc.sign(message, keyPair);
        const secondSignatureData = ecc.sign(message, keyPair);
        expect(firstSignatureData.nonce).not.toEqual(secondSignatureData.nonce);
    });

    test('Domain-specific seeds are distinct', () => {
        const networkSeed = ecc.deriveDomainSeed(baseSeed, 'network').toString('hex');
        const identitySeed = ecc.deriveDomainSeed(baseSeed, 'identity').toString('hex');
        const dataSeed = ecc.deriveDomainSeed(baseSeed, 'data').toString('hex');

        expect(networkSeed).not.toBe(identitySeed);
        expect(networkSeed).not.toBe(dataSeed);
        expect(identitySeed).not.toBe(dataSeed);
    });

    test('Ephemeral keys are unique for each session', () => {
        const ephemeralKeyPair1 = ecc.seedToKeyPair(ecc.generateRandomSeed(), 'ephemeral');
        const ephemeralKeyPair2 = ecc.seedToKeyPair(ecc.generateRandomSeed(), 'ephemeral');

        expect(ecc.getPublicKeyHex(ephemeralKeyPair1)).not.toBe(ecc.getPublicKeyHex(ephemeralKeyPair2));
    });

    test('Checksum validation detects errors in identity addresses', () => {
        const attribute = "example";
        const identityAddress = ecc.getIdentityPublicKeyHex(attribute, keyPairs.identity);

        console.log(`Identity Address: ${identityAddress}`);

        const alteredAddress = identityAddress.substring(0, identityAddress.length - 1) + (identityAddress[identityAddress.length - 1] === '1' ? '0' : '1');
        console.log(`Altered Address: ${alteredAddress}`);

        const isValid = ecc.verifyIdentityAddress(alteredAddress, attribute, keyPairs.identity);
        expect(isValid).toBeFalsy();
    });

    test('Regeneration of domain-specific keys is consistent', () => {
        const seed = ecc.generateRandomSeed();
        const domain = 'network';

        const keyPair1 = ecc.seedToKeyPair(seed, domain);
        const keyPair2 = ecc.seedToKeyPair(seed, domain);

        expect(ecc.getPublicKeyHex(keyPair1)).toBe(ecc.getPublicKeyHex(keyPair2));
    });
});
