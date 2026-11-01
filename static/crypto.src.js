import forge from 'node-forge';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';

const encoder = new TextEncoder();
const DB_NAME = 'qsytale';
const STORE = 'devices';
const RECORD_ID = 'current';
const AAD = encoder.encode('qsytale/device-keys/v1');

function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function fromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function openDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);

        request.onupgradeneeded = () => {
            request.result.createObjectStore(STORE, { keyPath: 'id' });
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function saveRecord(record) {
    const db = await openDB();

    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        tx.objectStore(STORE).put(record);
        tx.oncomplete = () => {
            db.close();
            resolve();
        };
        tx.onerror = () => {
            db.close();
            reject(tx.error);
        };
    });
}

async function readRecord() {
    const db = await openDB();

    return new Promise((resolve, reject) => {
        const request = db.transaction(STORE)
            .objectStore(STORE)
            .get(RECORD_ID);

        request.onsuccess = () => {
            db.close();
            resolve(request.result ?? null);
        };
        request.onerror = () => {
            db.close();
            reject(request.error);
        };
    });
}

async function deriveKey(passphrase, salt) {
    return scryptAsync(passphrase, salt, {
        N: 2 ** 15,
        r: 8,
        p: 1,
        dkLen: 32,
        asyncTick: 10,
    });
}

function generateRSAKeys() {
    return new Promise((resolve, reject) => {
        forge.pki.rsa.generateKeyPair(
            { bits: 2048, workers: -1 },
            (error, keypair) => {
                if (error) reject(error);
                else resolve(keypair);
            }
        );
    });
}

async function protectPrivateKeys(privateKeys, passphrase) {
    const salt = randomBytes(16);
    const nonce = randomBytes(12);
    const key = await deriveKey(passphrase, salt);

    const plaintext = encoder.encode(JSON.stringify(privateKeys));
    const ciphertext = gcm(key, nonce, AAD).encrypt(plaintext);

    return {
        salt: toBase64(salt),
        nonce: toBase64(nonce),
        ciphertext: toBase64(ciphertext),
    };
}

async function unprotectPrivateKeys(record, passphrase) {
    const key = await deriveKey(passphrase, fromBase64(record.salt));

    const plaintext = gcm(
        key,
        fromBase64(record.nonce),
        AAD
    ).decrypt(fromBase64(record.ciphertext));

    return JSON.parse(new TextDecoder().decode(plaintext));
}

export async function generateDeviceKeys(passphrase) {
    if (!passphrase || passphrase.length < 8) {
        throw new Error('Use a passphrase of at least 8 characters.');
    }

    // Generate both keypairs locally.
    const rsa = await generateRSAKeys();
    const kem = ml_kem768.keygen();

    const rsaPublic = forge.pki.publicKeyToPem(rsa.publicKey);
    const rsaPrivate = forge.pki.privateKeyToPem(rsa.privateKey);

    const privateKeys = {
        rsaPrivate,
        mlkemSecret: toBase64(kem.secretKey),
    };

    // Encrypt private keys before writing anything to IndexedDB.
    const protectedKeys = await protectPrivateKeys(
        privateKeys,
        passphrase
    );

    const record = {
        id: RECORD_ID,
        ...protectedKeys,
        rsaPublic,
        mlkemPublic: toBase64(kem.publicKey),
        created: new Date().toISOString(),
    };

    await saveRecord(record);

    return {
        rsa_pk: rsaPublic,
        mlkem_pk: record.mlkemPublic,
        rsaPublicBytes: forge.util.decode64(
            forge.util.encode64(
              forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsa.publicKey)).getBytes()
            )
        ).length,
        mlkemPublicBytes: kem.publicKey.length,
    };
}

export async function unlockDevice(passphrase) {
    const record = await readRecord();

    if (!record) {
        throw new Error('No enrolled device keys found on this browser.');
    }

    const privateKeys = await unprotectPrivateKeys(record, passphrase);

    return {
        rsaPrivate: forge.pki.privateKeyFromPem(privateKeys.rsaPrivate),
        mlkemSecret: fromBase64(privateKeys.mlkemSecret),
        rsaPublic: record.rsaPublic,
        mlkemPublic: fromBase64(record.mlkemPublic),
    };
}

export async function getStoredDevice() {
    const record = await readRecord();
    if (!record) return null;

    return {
        rsa_pk: record.rsaPublic,
        mlkem_pk: record.mlkemPublic,
        created: record.created,
    };
}
