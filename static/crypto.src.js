import forge from 'node-forge';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

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

// ==================================================
// FILE VAULT: CLASSICAL MODE
//   file   : AES-256-GCM under a random 32-byte FEK
//   FEK    : wrapped per device with RSA-OAEP (SHA-256, MGF1-SHA-256)
//   AAD    : binds ciphertext and metadata to the file id
// Nothing below sends plaintext, the FEK or a private key to the server.
// ==================================================

export const MAX_FILE_SIZE = 20 * 1024 * 1024;
const MODE_CLASSICAL = 'classical';
const RSA_WRAP_ALG = 'RSA-OAEP-SHA256';

const blobAad = (fileId) => encoder.encode(`qsytale/v1/blob/${fileId}`);
const metaAad = (fileId) => encoder.encode(`qsytale/v1/meta/${fileId}`);

function oaepOptions() {
    return {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() },
    };
}

function bytesToBinary(bytes) {
    return forge.util.binary.raw.encode(bytes);
}

function binaryToBytes(binary) {
    return forge.util.binary.raw.decode(binary);
}

export function sha256Hex(bytes) {
    return bytesToHex(sha256(bytes));
}

function wrapFekRSA(rsaPublicPem, fek) {
    const publicKey = forge.pki.publicKeyFromPem(rsaPublicPem);
    const ciphertext = publicKey.encrypt(
        bytesToBinary(fek),
        'RSA-OAEP',
        oaepOptions()
    );

    return { alg: RSA_WRAP_ALG, ct: toBase64(binaryToBytes(ciphertext)) };
}

function unwrapFekRSA(rsaPrivateKey, wrap) {
    if (wrap.alg !== RSA_WRAP_ALG) {
        throw new Error(`Unsupported wrap algorithm: ${wrap.alg}`);
    }

    const plaintext = rsaPrivateKey.decrypt(
        bytesToBinary(fromBase64(wrap.ct)),
        'RSA-OAEP',
        oaepOptions()
    );

    const fek = binaryToBytes(plaintext);

    if (fek.length !== 32) throw new Error('Unwrapped key has wrong length.');

    return fek;
}

// Pure function: no network, no storage.
// devices = [{ id, rsa_pk }] for EVERY enrolled device (server requires it).
export function encryptFileClassical({ bytes, name, type, devices }) {
    if (bytes.length > MAX_FILE_SIZE) {
        throw new Error('File exceeds the 20 MiB limit.');
    }

    const fileId = bytesToHex(randomBytes(16));
    const fek = randomBytes(32);
    const nonce = randomBytes(12);
    const metaNonce = randomBytes(12);

    const blob = gcm(fek, nonce, blobAad(fileId)).encrypt(bytes);

    const metaPlain = encoder.encode(
        JSON.stringify({ name, type, size: bytes.length })
    );
    const metaCt = gcm(fek, metaNonce, metaAad(fileId)).encrypt(metaPlain);

    const wraps = devices.map((device) => ({
        device_id: device.id,
        wrap_json: wrapFekRSA(device.rsa_pk, fek),
    }));

    fek.fill(0);

    return {
        fileId,
        blob,
        metadata: {
            file_id: fileId,
            mode: MODE_CLASSICAL,
            nonce: toBase64(nonce),
            meta_nonce: toBase64(metaNonce),
            meta_ct: toBase64(metaCt),
            size: bytes.length,
        },
        wraps,
    };
}

// Pure function: returns { fek, name, type, size } for a file entry.
export function openFileMetadata({ rsaPrivate, entry, wrap }) {
    const fek = unwrapFekRSA(rsaPrivate, wrap);

    const plain = gcm(
        fek,
        fromBase64(entry.meta_nonce),
        metaAad(entry.id)
    ).decrypt(fromBase64(entry.meta_ct));

    const meta = JSON.parse(new TextDecoder().decode(plain));

    return { fek, name: meta.name, type: meta.type, size: meta.size };
}

// Pure function: returns plaintext bytes; throws if anything was tampered with.
export function decryptBlob({ fek, entry, ciphertext, expectedSize }) {
    const plain = gcm(
        fek,
        fromBase64(entry.nonce),
        blobAad(entry.id)
    ).decrypt(ciphertext);

    if (plain.length !== expectedSize) {
        throw new Error('Decrypted size does not match the file metadata.');
    }

    return plain;
}

// ---------- network helpers (ctx = { token, baseUrl }) ----------

async function api(ctx, path, options = {}) {
    const response = await fetch(`${ctx.baseUrl ?? ''}${path}`, {
        ...options,
        headers: {
            ...(options.headers ?? {}),
            Authorization: `Bearer ${ctx.token}`,
        },
    });

    if (!response.ok) {
        let detail = '';
        try {
            detail = (await response.json()).detail ?? '';
        } catch {
            // body was not JSON
        }
        throw new Error(`${path} failed: ${response.status} ${detail}`);
    }

    return response;
}

export async function uploadFileClassical(ctx, { bytes, name, type }) {
    const devices = await (await api(ctx, '/api/devices')).json();

    const sealed = encryptFileClassical({ bytes, name, type, devices });

    const form = new FormData();
    form.append(
        'blob',
        new Blob([sealed.blob], { type: 'application/octet-stream' }),
        'blob.bin'
    );
    form.append('metadata', JSON.stringify(sealed.metadata));
    form.append('wraps', JSON.stringify(sealed.wraps));

    const result = await (
        await api(ctx, '/api/files', { method: 'POST', body: form })
    ).json();

    return {
        id: result.id,
        storedBytes: result.stored_bytes,
        wrappedFor: result.wrapped_for,
        plaintextSha256: sha256Hex(bytes),
    };
}

// Lists files and decrypts each name for this device.
// Entries keep their FEK in memory only, for downloadFile().
export async function listVault(ctx, rsaPrivate) {
    const entries = await (await api(ctx, '/api/files')).json();
    const result = [];

    for (const entry of entries) {
        const item = {
            id: entry.id,
            mode: entry.mode,
            uploader: entry.uploader,
            created: entry.created,
            raw: entry,
        };

        try {
            if (entry.mode !== MODE_CLASSICAL) {
                throw new Error(`mode "${entry.mode}" not supported yet`);
            }

            const { wrap } = await (
                await api(ctx, `/api/files/${entry.id}/wrap`)
            ).json();

            const opened = openFileMetadata({ rsaPrivate, entry, wrap });

            item.fek = opened.fek;
            item.name = opened.name;
            item.type = opened.type;
            item.size = opened.size;
        } catch (error) {
            item.error = error.message;
        }

        result.push(item);
    }

    return result;
}

export async function downloadFile(ctx, item) {
    if (!item.fek) throw new Error('No file key available for this item.');

    const response = await api(ctx, `/api/files/${item.id}/blob`);
    const ciphertext = new Uint8Array(await response.arrayBuffer());

    const bytes = decryptBlob({
        fek: item.fek,
        entry: item.raw,
        ciphertext,
        expectedSize: item.size,
    });

    return {
        bytes,
        name: item.name,
        type: item.type,
        sha256: sha256Hex(bytes),
    };
}
