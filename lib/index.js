const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const crypto = require('crypto');

class Ecc {
    constructor(prefix = 'Yo') {
        this.prefix = prefix;
    }

    generateRandomSeed(length = 64) {
        return crypto.randomBytes(length);
    }

    deriveDomainSeed(seedBytes, domain) {
        if (!(seedBytes instanceof Buffer) || seedBytes.length !== 64) {
            throw new Error('Seed bytes must be a valid bip39 64-byte Buffer.');
        }
        const domainAlgorithms = {
            'network': 'sha512',
            'identity': 'sha512',
            'data': 'sha512',
            'ephemeral': 'sha256'
        };

        const algorithm = domainAlgorithms[domain];
        if (!algorithm) {
            throw new Error('Invalid domain specified.');
        }

        const hash = crypto.createHash(algorithm);
        hash.update(domain);
        hash.update(seedBytes);
        return hash.digest();
    }

    seedToKeyPair(seedBytes, domain = '') {
        const allowedLengths = [32, 64];

        if (!(seedBytes instanceof Buffer) || !allowedLengths.includes(seedBytes.length)) {
            throw new Error('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
        }

        const finalSeed = (domain === 'ephemeral') ? this.generateRandomSeed() : (domain ? this.deriveDomainSeed(seedBytes, domain) : seedBytes);

        return ec.keyFromPrivate(finalSeed);
    }

    getPublicKey(keyPair) {
        return keyPair.getPublic();
    }

    getPrivateKey(keyPair) {
        return keyPair.getPrivate();
    }

    getPublicKeyHex(keyPair) {
        return this.getPublicKey(keyPair).encode('hex', false);
    }

    getPrivateKeyHex(keyPair) {
        return this.getPrivateKey(keyPair).toString('hex');
    }

    publicKeyFromHex(publicKeyHex) {
        return ec.keyFromPublic(publicKeyHex, 'hex');
    }

    hashMessage(message) {
        return crypto.createHash('sha256').update(message).digest();
    }

    sign(message, keyPair, nonce = null) {
        if (!nonce) {
            nonce = crypto.randomBytes(16).toString('hex');
        }

        const timestamp = Date.now();
        const messageWithMeta = `${message}|${nonce}|${timestamp}`;
        const msgHash = this.hashMessage(messageWithMeta);
        const signature = keyPair.sign(msgHash);

        return {
            signature: signature.toDER('hex'),
            nonce: nonce,
            timestamp: timestamp
        };
    }

    verify(message, signature, nonce, timestamp, keyPair, validity = 60 * 1000) {
        const currentTime = Date.now();
        const timeDifference = currentTime - timestamp;
        if (timeDifference > validity) {
            throw new Error('Message timestamp is outside the validity period.');
        }

        const messageWithMeta = `${message}|${nonce}|${timestamp}`;
        const msgHash = this.hashMessage(messageWithMeta);
        return keyPair.verify(msgHash, signature);
    }

    getIdentityPublicKeyHex(attr, keyPair, length = 20) {
        const publicKeyHex = this.getPublicKeyHex(keyPair);
        const combinedInput = attr + publicKeyHex;
        const fullHash = crypto.createHash('sha256').update(combinedInput).digest('hex');
        const shortHash = fullHash.substring(0, length * 2);

        const checksumLength = 4;
        const checksum = crypto.createHash('sha256').update(shortHash).digest('hex').substring(0, checksumLength * 2);

        return this.prefix + shortHash + checksum;
    }

    verifyIdentityAddress(providedAddress, attr, publicKey) {
        if (!providedAddress.startsWith(this.prefix)) {
            return false;
        }

        const addressWithoutPrefix = providedAddress.slice(this.prefix.length);
        const publicKeyHex = this.getPublicKeyHex(publicKey);
        const combinedInput = attr + publicKeyHex;
        const fullHash = crypto.createHash('sha256').update(combinedInput).digest('hex');

        const length = (addressWithoutPrefix.length - 8) / 2;
        const shortHash = fullHash.substring(0, length * 2);

        const checksumLength = 4;
        const checksum = crypto.createHash('sha256').update(shortHash).digest('hex').substring(0, checksumLength * 2);

        const regeneratedAddress = shortHash + checksum;

        return addressWithoutPrefix === regeneratedAddress;
    }

    generateSharedExchangeKey(keyPair, recipientPublicKeyHex) {
        const recipientPublicKey = this.publicKeyFromHex(recipientPublicKeyHex);
        return keyPair.derive(recipientPublicKey.getPublic());
    }

    generateSharedExchangeKeyHex(keyPair, recipientPublicKeyHex) {
        const recipientPublicKey = this.publicKeyFromHex(recipientPublicKeyHex);
        return keyPair.derive(recipientPublicKey.getPublic()).toString('hex');
    }
    generateSharedExchangeKeyBN(keyPair, recipientPublicKeyHex) {
        const recipientPublicKey = this.publicKeyFromHex(recipientPublicKeyHex);
        return keyPair.derive(recipientPublicKey.getPublic()).toString(16);
    }

    convertSharedExchangeKeyToBuffer(sharedExchangeKey) {
        return Buffer.from(sharedExchangeKey.toArray(Buffer));
    }

    encryptWithSharedExchangeKey(message, sharedExchangeKey) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-gcm', sharedExchangeKey, iv);
        const encrypted = cipher.update(message, 'utf8');
        const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();
        return Buffer.concat([iv, authTag, finalBuffer]).toString('hex');
    }

    decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKey) {
        const data = Buffer.from(encryptedMessage, 'hex');
        const iv = data.slice(0, 16);
        const authTag = data.slice(16, 32);
        const encrypted = data.slice(32);
        const decipher = crypto.createDecipheriv('aes-256-gcm', sharedExchangeKey, iv);
        decipher.setAuthTag(authTag);
        return decipher.update(encrypted) + decipher.final('utf8');
    }
}

module.exports = Ecc;
