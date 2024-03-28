const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const crypto = require('crypto');



function seedToKeyPair(seedBytes) {
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


function sign(message, keyPair) {
    let msgHash = ec.hash().update(message).digest();
    let signature = keyPair.sign(msgHash);
    return signature.toDER('hex');
}

function verify(message, signature, keyPair) {
    let msgHash = ec.hash().update(message).digest();
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
    const cipher = crypto.createCipheriv('aes-256-cbc', sharedExchangeKey, iv);
    const encrypted = Buffer.concat([cipher.update(message), cipher.final()]);
    const ivHex = iv.toString('hex');
    const encryptedHex = encrypted.toString('hex');
    return ivHex + encryptedHex;
}

function decryptWithSharedExchangeKey(encryptedMessage, sharedExchangeKey) {
    const ivHex = encryptedMessage.slice(0, 32);
    const encryptedHex = encryptedMessage.slice(32);
    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', sharedExchangeKey, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString();
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
    decryptWithSharedExchangeKey
}