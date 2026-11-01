import forge from 'node-forge';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
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

// ==================================================
// FILE VAULT: POST-QUANTUM MODE (added after classical, same blob format)
//   file   : identical to classical (AES-256-GCM under a random FEK)
//   FEK    : per device, (kem_ct, ss) = ML-KEM-768.Encaps(device pk)
//            k = HKDF-SHA-256(ss, info = file id + device id)
//            wrapped = AES-256-GCM(k, wnonce, FEK, aad = file id + device id)
// ==================================================

const MODE_PQ = 'post-quantum';
const PQ_WRAP_ALG = 'ML-KEM-768+HKDF-SHA256+AES-256-GCM';

const pqInfo = (fileId, deviceId) =>
    encoder.encode(`qsytale/v1/mlkem-wrap/${fileId}/${deviceId}`);
const pqWrapAad = (fileId, deviceId) =>
    encoder.encode(`qsytale/v1/mlkem-wrap-aad/${fileId}/${deviceId}`);

function wrapFekMLKEM(mlkemPublicB64, fek, fileId, deviceId) {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(
        fromBase64(mlkemPublicB64)
    );
    const k = hkdf(sha256, sharedSecret, undefined, pqInfo(fileId, deviceId), 32);
    const wnonce = randomBytes(12);
    const wrapped = gcm(k, wnonce, pqWrapAad(fileId, deviceId)).encrypt(fek);

    k.fill(0);
    sharedSecret.fill(0);

    return {
        alg: PQ_WRAP_ALG,
        kem_ct: toBase64(cipherText),
        wnonce: toBase64(wnonce),
        wrapped: toBase64(wrapped),
    };
}

function unwrapFekMLKEM(mlkemSecret, wrap, fileId, deviceId) {
    const sharedSecret = ml_kem768.decapsulate(
        fromBase64(wrap.kem_ct),
        mlkemSecret
    );
    const k = hkdf(sha256, sharedSecret, undefined, pqInfo(fileId, deviceId), 32);
    const fek = gcm(
        k,
        fromBase64(wrap.wnonce),
        pqWrapAad(fileId, deviceId)
    ).decrypt(fromBase64(wrap.wrapped));

    k.fill(0);
    sharedSecret.fill(0);

    if (fek.length !== 32) throw new Error('Unwrapped key has wrong length.');

    return fek;
}

// Pure function: no network, no storage.
// devices = [{ id, rsa_pk, mlkem_pk }] for EVERY enrolled device (server requires it).
// mode = 'classical' (default) or 'post-quantum'.
export function encryptFile({ bytes, name, type, devices, mode = MODE_CLASSICAL }) {
    if (mode !== MODE_CLASSICAL && mode !== MODE_PQ) {
        throw new Error(`Unknown encryption mode: ${mode}`);
    }

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
        wrap_json: mode === MODE_PQ
            ? wrapFekMLKEM(device.mlkem_pk, fek, fileId, device.id)
            : wrapFekRSA(device.rsa_pk, fek),
    }));

    fek.fill(0);

    return {
        fileId,
        blob,
        metadata: {
            file_id: fileId,
            mode,
            nonce: toBase64(nonce),
            meta_nonce: toBase64(metaNonce),
            meta_ct: toBase64(metaCt),
            size: bytes.length,
        },
        wraps,
    };
}

// Unchanged public name and behaviour for classical callers.
export function encryptFileClassical(args) {
    return encryptFile({ ...args, mode: MODE_CLASSICAL });
}

// Pure function: returns { fek, name, type, size } for a file entry.
// Dispatches on the wrap algorithm, so old classical files keep working.
export function openFileMetadata({ rsaPrivate, mlkemSecret, deviceId, entry, wrap }) {
    let fek;

    if (wrap.alg === RSA_WRAP_ALG) {
        fek = unwrapFekRSA(rsaPrivate, wrap);
    } else if (wrap.alg === PQ_WRAP_ALG) {
        if (!mlkemSecret || !deviceId) {
            throw new Error('ML-KEM secret key and device id are required.');
        }
        fek = unwrapFekMLKEM(mlkemSecret, wrap, entry.id, deviceId);
    } else {
        throw new Error(`Unsupported wrap algorithm: ${wrap.alg}`);
    }

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

export async function uploadFile(ctx, { bytes, name, type, mode = MODE_CLASSICAL }) {
    const devices = await (await api(ctx, '/api/devices')).json();

    const sealed = encryptFile({ bytes, name, type, devices, mode });

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
        mode,
        storedBytes: result.stored_bytes,
        wrappedFor: result.wrapped_for,
        plaintextSha256: sha256Hex(bytes),
    };
}

export function uploadFileClassical(ctx, args) {
    return uploadFile(ctx, { ...args, mode: MODE_CLASSICAL });
}

// Lists files and decrypts each name for this device.
// Entries keep their FEK in memory only, for downloadFile().
export async function listVault(ctx, rsaPrivate, mlkemSecret = null, deviceId = null) {
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
            if (entry.mode !== MODE_CLASSICAL && entry.mode !== MODE_PQ) {
                throw new Error(`mode "${entry.mode}" not supported`);
            }

            const { wrap } = await (
                await api(ctx, `/api/files/${entry.id}/wrap`)
            ).json();

            const opened = openFileMetadata({
                rsaPrivate, mlkemSecret, deviceId, entry, wrap,
            });

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

// ==================================================
// BENCHMARK: RSA-2048 vs ML-KEM-768, measured on THIS device
// Times the same wrap/unwrap code paths the vault uses. Nothing is hardcoded:
// every size and timing below is measured from real keys and real wraps.
// ==================================================

function median(values) {
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

function timeIt(runs, fn) {
    const samples = [];
    for (let i = 0; i < runs; i++) {
        const start = performance.now();
        fn();
        samples.push(performance.now() - start);
    }
    return median(samples);
}

const utf8Length = (text) => encoder.encode(text).length;

// iterations: runs for the fast operations (wrap, unwrap, ML-KEM keygen).
// rsaKeygenRuns: RSA-2048 keygen is slow (seconds on a phone), so fewer runs.
export async function runBenchmark({ iterations = 20, rsaKeygenRuns = 5, onProgress = () => {} } = {}) {
    // ---- RSA keygen (async, same call the app uses at enrolment) ----
    const rsaKeygenSamples = [];
    let rsa;
    for (let i = 0; i < rsaKeygenRuns; i++) {
        onProgress(`RSA-2048 keygen ${i + 1}/${rsaKeygenRuns}...`);
        const start = performance.now();
        rsa = await generateRSAKeys();
        rsaKeygenSamples.push(performance.now() - start);
    }

    // ---- ML-KEM keygen ----
    onProgress('ML-KEM-768 keygen...');
    const kemKeygenMs = timeIt(iterations, () => ml_kem768.keygen());
    const kem = ml_kem768.keygen();

    const rsaPem = forge.pki.publicKeyToPem(rsa.publicKey);
    const kemPkB64 = toBase64(kem.publicKey);
    const fek = randomBytes(32);
    const fileId = bytesToHex(randomBytes(16));
    const deviceId = bytesToHex(randomBytes(8));

    // ---- wrap / unwrap ----
    onProgress('RSA-OAEP wrap/unwrap...');
    const rsaWrap = wrapFekRSA(rsaPem, fek);
    const rsaWrapMs = timeIt(iterations, () => wrapFekRSA(rsaPem, fek));
    const rsaUnwrapMs = timeIt(iterations, () => unwrapFekRSA(rsa.privateKey, rsaWrap));

    onProgress('ML-KEM-768 wrap/unwrap...');
    const kemWrap = wrapFekMLKEM(kemPkB64, fek, fileId, deviceId);
    const kemWrapMs = timeIt(iterations, () => wrapFekMLKEM(kemPkB64, fek, fileId, deviceId));
    const kemUnwrapMs = timeIt(iterations, () => unwrapFekMLKEM(kem.secretKey, kemWrap, fileId, deviceId));

    // Sanity: both wraps must actually recover the FEK.
    const rsaOk = unwrapFekRSA(rsa.privateKey, rsaWrap).every((b, i) => b === fek[i]);
    const kemOk = unwrapFekMLKEM(kem.secretKey, kemWrap, fileId, deviceId).every((b, i) => b === fek[i]);
    if (!rsaOk || !kemOk) throw new Error('Benchmark self-check failed: unwrap did not recover the FEK.');

    // ---- sizes (bytes) ----
    const rsaPublicDer = forge.asn1.toDer(forge.pki.publicKeyToAsn1(rsa.publicKey)).getBytes().length;
    const rsaPrivateDer = forge.asn1.toDer(forge.pki.privateKeyToAsn1(rsa.privateKey)).getBytes().length;

    const rsaWrapBytes = binaryToBytes(forge.util.decode64(rsaWrap.ct)).length;
    const kemWrapBytes =
        fromBase64(kemWrap.kem_ct).length +
        fromBase64(kemWrap.wnonce).length +
        fromBase64(kemWrap.wrapped).length;

    // What the server stores for 2 devices and 1 file: each device's public
    // keys as stored (PEM / base64 text) plus each device's wrap JSON.
    const rsaServer2 = 2 * (utf8Length(rsaPem) + utf8Length(JSON.stringify(rsaWrap)));
    const kemServer2 = 2 * (utf8Length(kemPkB64) + utf8Length(JSON.stringify(kemWrap)));

    return {
        device: typeof navigator !== 'undefined' ? navigator.userAgent : 'node',
        iterations,
        rsaKeygenRuns,
        rsa: {
            keygenMs: median(rsaKeygenSamples),
            publicKeyBytes: rsaPublicDer,
            privateKeyBytes: rsaPrivateDer,
            wrapBytes: rsaWrapBytes,
            wrapMs: rsaWrapMs,
            unwrapMs: rsaUnwrapMs,
            serverBytes2Devices: rsaServer2,
        },
        mlkem: {
            keygenMs: kemKeygenMs,
            publicKeyBytes: kem.publicKey.length,
            privateKeyBytes: kem.secretKey.length,
            wrapBytes: kemWrapBytes,
            wrapMs: kemWrapMs,
            unwrapMs: kemUnwrapMs,
            serverBytes2Devices: kemServer2,
        },
    };
}
