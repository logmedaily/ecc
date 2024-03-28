const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const crypto = require('crypto');



function deriveDomainSeed(seedBytes, domain) {
    if (!(seedBytes instanceof Buffer) || seedBytes.length !== 64) {
        throw new Error('Seed bytes must be a valid bip39 64-byte Buffer.');
    }
    const domainAlgorithms = {
        'network': 'sha256',
        'identity': 'sha256',
        'data': 'sha512'
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


function seedToKeyPair(seedBytes) {
    const allowedLengths = [32, 64];

    if (!(seedBytes instanceof Buffer) || !allowedLengths.includes(seedBytes.length)) {
        throw new Error('Seed bytes must be provided as a Buffer with a length of 32, or 64 bytes.');
    }

    return ec.keyFromPrivate(seedBytes);
}

function getPublicKey(keyPair) {
    return keyPair.getPublic();
}

function getPrivateKey(keyPair) {
    return keyPair.getPrivate();
}

function getPublicKeyHex(keyPair) {
    return getPublicKey(keyPair).encode('hex', false);
}

function getPrivateKeyHex(keyPair) {
    return getPrivateKey(keyPair).toString('hex');
}

function publicKeyFromHex(publicKeyHex) {
    return ec.keyFromPublic(publicKeyHex, 'hex');
}

function hashMessage(message) {
    return crypto.createHash('sha256').update(message).digest();
}

function sign(message, keyPair, nonce = null) {
    if (!nonce) {
        nonce = crypto.randomBytes(16).toString('hex');
    }

    const timestamp = Date.now();
    const messageWithMeta = `${message}|${nonce}|${timestamp}`;
    const msgHash = hashMessage(messageWithMeta);
    const signature = keyPair.sign(msgHash);

    return {
        signature: signature.toDER('hex'),
        nonce: nonce,
        timestamp: timestamp
    };
}

function verify(message, signature, nonce, timestamp, keyPair, validity) {
    const currentTime = Date.now();
    const timeDifference = currentTime - timestamp;
    const validityPeriod = validity || 60 * 1000  ; // one minute for testing

    if (timeDifference > validityPeriod) {
        throw new Error('Message timestamp is outside the validity period.');
    }

    const messageWithMeta = `${message}|${nonce}|${timestamp}`;
    const msgHash = hashMessage(messageWithMeta);
    return keyPair.verify(msgHash, signature);
}

function generateSharedExchangeKeyBN(keyPair, recipientPublicKey) {
    return keyPair.derive(recipientPublicKey).toString(16);
}

function generateSharedExchangeKeyHex(keyPair, recipientPublicKey) {
    return keyPair.derive(recipientPublicKey).toString('hex');
}

function generateSharedExchangeKey(keyPair, recipientPublicKey) {
    return keyPair.derive(recipientPublicKey);
}

function convertSharedExchangeKeyToBuffer(sharedExchangeKey) {
    return Buffer.from(sharedExchangeKey.toArray(Buffer));
}

function encryptWithSharedExchangeKey(message, sharedExchangeKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', sharedExchangeKey, iv);
    const encrypted = cipher.update(message, 'utf8');
    const finalBuffer = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, finalBuffer]).toString('hex');
}

function decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKey) {
    const data = Buffer.from(encryptedMessage, 'hex');
    const iv = data.slice(0, 16);
    const authTag = data.slice(16, 32);
    const encrypted = data.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedExchangeKey, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(encrypted) + decipher.final('utf8');
}

// not tested
function createEncryptionStream(sharedExchangeKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', sharedExchangeKey, iv);

    process.nextTick(() => {
        console.log('IV:', iv.toString('hex'));
    });

    cipher.on('end', () => {
        console.log('Auth Tag:', cipher.getAuthTag().toString('hex'));
    });
    return cipher;
}

// not tested
function createDecryptionStream(sharedExchangeKey, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', sharedExchangeKey, iv);
    decipher.setAuthTag(authTag);
    return decipher;
}

module.exports = {
    seedToKeyPair,
    getPublicKey,
    getPrivateKey,
    getPublicKeyHex,
    getPrivateKeyHex,
    sign,
    verify,
    generateSharedExchangeKeyBN,
    generateSharedExchangeKeyHex,
    generateSharedExchangeKey,
    convertSharedExchangeKeyToBuffer,
    encryptWithSharedExchangeKey,
    decryptWithSharedExchangeKey,
    deriveDomainSeed,
    publicKeyFromHex
}