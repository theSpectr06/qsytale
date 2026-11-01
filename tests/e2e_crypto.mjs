// End-to-end test: real FastAPI server, real HTTP, two simulated devices.
// Run via tests/run_e2e.sh (starts the server with a throwaway database).
import forge from 'node-forge';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
    uploadFile, listVault, downloadFile, sha256Hex, encryptFile, openFileMetadata,
} from '../static/crypto.src.js';

import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = process.env.PORT || '18765';
const BASE = `http://127.0.0.1:${PORT}`;
const DATA = mkdtempSync(join(tmpdir(), 'qsytale-test-'));   // throwaway DB, never data/
let server = null;

// The server prints a fresh one-use invite on every start; the database persists.
function startServer() {
    return new Promise((resolve, reject) => {
        server = spawn('uv', ['run', 'uvicorn', 'server:app', '--host', '127.0.0.1', '--port', PORT],
            { env: { ...process.env, QSYTALE_DATA_DIR: DATA }, stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '';
        const onData = (d) => {
            out += d;
            const m = out.match(/one use\): (\S+)/);
            if (m && out.includes('startup complete')) resolve(m[1]);
        };
        server.stdout.on('data', onData); server.stderr.on('data', onData);
        setTimeout(() => reject(new Error('server start timeout: ' + out)), 20000);
    });
}
function stopServer() {
    return new Promise((r) => { if (!server) return r(); server.once('exit', r); server.kill(); });
}
const b64 = (u8) => Buffer.from(u8).toString('base64');
let passed = 0, failed = 0;

function check(name, cond, extra = '') {
    if (cond) { passed++; console.log(`PASS  ${name}`); }
    else { failed++; console.log(`FAIL  ${name} ${extra}`); }
}
async function expectThrow(name, fn) {
    try { await fn(); check(name, false, '(no error thrown)'); }
    catch (e) { check(name, true); }
}

async function makeDevice(name, invite) {
    const rsa = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const kem = ml_kem768.keygen();
    const rsa_pk = forge.pki.publicKeyToPem(rsa.publicKey);
    const mlkem_pk = b64(kem.publicKey);
    const r = await fetch(`${BASE}/api/enroll`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invite_code: invite, name, rsa_pk, mlkem_pk }),
    });
    if (!r.ok) throw new Error(`enroll ${name}: ${r.status}`);
    const { device_id, token } = await r.json();
    return { id: device_id, ctx: { token, baseUrl: BASE }, rsaPrivate: rsa.privateKey, mlkemSecret: kem.secretKey };
}

const A = await makeDevice('Laptop', await startServer());
await stopServer();
const B = await makeDevice('Phone', await startServer());   // restart => fresh invite, same DB

const payload = new Uint8Array(100_003).map((_, i) => (i * 31 + 7) & 255);
const hash = sha256Hex(payload);

async function roundTrip(sender, receiver, mode, label) {
    const up = await uploadFile(sender.ctx, { bytes: payload, name: `${label}.bin`, type: 'application/octet-stream', mode });
    check(`${label}: upload ok, wrapped for 2 devices`, up.wrappedFor === 2);
    const items = await listVault(receiver.ctx, receiver.rsaPrivate, receiver.mlkemSecret, receiver.id);
    const item = items.find((i) => i.id === up.id);
    check(`${label}: receiver lists file with decrypted name and mode ${mode}`, item && !item.error && item.name === `${label}.bin` && item.mode === mode, item?.error);
    const out = await downloadFile(receiver.ctx, item);
    check(`${label}: recovered SHA-256 matches original`, out.sha256 === hash);
    return up.id;
}

const idC1 = await roundTrip(A, B, 'classical', 'classical A->B');
const idC2 = await roundTrip(B, A, 'classical', 'classical B->A');
const idP1 = await roundTrip(A, B, 'post-quantum', 'pq A->B');
const idP2 = await roundTrip(B, A, 'post-quantum', 'pq B->A');

// Backward compatibility: earlier classical files still open next to PQ ones.
const mixed = await listVault(A.ctx, A.rsaPrivate, A.mlkemSecret, A.id);
check('mixed vault: all 4 files readable', mixed.length === 4 && mixed.every((i) => !i.error));
check('mixed vault: both modes present', new Set(mixed.map((i) => i.mode)).size === 2);

// Old call signature (RSA key only) still works for classical files.
const legacy = await listVault(A.ctx, A.rsaPrivate);
const legacyOk = legacy.filter((i) => i.mode === 'classical').every((i) => !i.error);
const legacyPq = legacy.filter((i) => i.mode === 'post-quantum').every((i) => i.error);
check('legacy listVault(ctx, rsaPrivate): classical readable, PQ cleanly refused', legacyOk && legacyPq);

// Server stores no plaintext / FEK: ciphertext does not contain payload bytes.
const blob = new Uint8Array(await (await fetch(`${BASE}/api/files/${idP1}/blob`, { headers: { Authorization: `Bearer ${A.ctx.token}` } })).arrayBuffer());
check('blob length = plaintext + 16-byte GCM tag', blob.length === payload.length + 16);
check('blob differs from plaintext', Buffer.compare(Buffer.from(blob.slice(0, 64)), Buffer.from(payload.slice(0, 64))) !== 0);

// Wrap sizes (measured).
const wrapPq = (await (await fetch(`${BASE}/api/files/${idP1}/wrap`, { headers: { Authorization: `Bearer ${A.ctx.token}` } })).json()).wrap;
const wrapRsa = (await (await fetch(`${BASE}/api/files/${idC1}/wrap`, { headers: { Authorization: `Bearer ${A.ctx.token}` } })).json()).wrap;
check('PQ wrap: kem_ct is 1088 bytes', Buffer.from(wrapPq.kem_ct, 'base64').length === 1088);
check('PQ wrap: wrapped FEK is 48 bytes (32 + tag)', Buffer.from(wrapPq.wrapped, 'base64').length === 48);
check('RSA wrap: ct is 256 bytes', Buffer.from(wrapRsa.ct, 'base64').length === 256);

// Tamper / misuse tests.
const itemP = mixed.find((i) => i.id === idP1);
await expectThrow('tampered ciphertext is rejected', async () => {
    const bad = new Uint8Array(blob); bad[10] ^= 1;
    const { decryptBlob } = await import('../static/crypto.src.js');
    decryptBlob({ fek: itemP.fek, entry: itemP.raw, ciphertext: bad, expectedSize: itemP.size });
});
await expectThrow('wrong device cannot unwrap PQ wrap meant for another device', async () => {
    openFileMetadata({ rsaPrivate: B.rsaPrivate, mlkemSecret: B.mlkemSecret, deviceId: B.id, entry: itemP.raw, wrap: wrapPq }); // wrapPq is A's wrap
});
await expectThrow('PQ wrap fails if device id (HKDF/AAD binding) is wrong', async () => {
    openFileMetadata({ rsaPrivate: A.rsaPrivate, mlkemSecret: A.mlkemSecret, deviceId: B.id, entry: itemP.raw, wrap: wrapPq });
});
await expectThrow('PQ wrap fails if bound to a different file id', async () => {
    openFileMetadata({ rsaPrivate: A.rsaPrivate, mlkemSecret: A.mlkemSecret, deviceId: A.id, entry: { ...itemP.raw, id: 'f'.repeat(32) }, wrap: wrapPq });
});
await expectThrow('tampered KEM ciphertext is rejected', async () => {
    const t = { ...wrapPq, kem_ct: Buffer.from(Buffer.from(wrapPq.kem_ct, 'base64').map((x, i) => (i === 5 ? x ^ 1 : x))).toString('base64') };
    openFileMetadata({ rsaPrivate: A.rsaPrivate, mlkemSecret: A.mlkemSecret, deviceId: A.id, entry: itemP.raw, wrap: t });
});
await expectThrow('unknown mode rejected client-side', async () => {
    encryptFile({ bytes: payload, name: 'x', type: '', devices: [], mode: 'rot13' });
});

// Server rejects an unknown mode and missing wraps.
const form = new FormData();
form.append('blob', new Blob([new Uint8Array(32)]), 'b.bin');
form.append('metadata', JSON.stringify({ file_id: 'a'.repeat(32), mode: 'rot13', nonce: b64(new Uint8Array(12)), meta_nonce: b64(new Uint8Array(12)), meta_ct: b64(new Uint8Array(20)), size: 1 }));
form.append('wraps', '[]');
const bad = await fetch(`${BASE}/api/files`, { method: 'POST', body: form, headers: { Authorization: `Bearer ${A.ctx.token}` } });
check('server rejects invalid mode (400)', bad.status === 400);
const unauth = await fetch(`${BASE}/api/files`);
check('unauthenticated request gets 401', unauth.status === 401);

// Quantum lab endpoint (local Qiskit Aer).
const H = { Authorization: `Bearer ${A.ctx.token}`, 'Content-Type': 'application/json' };
const lab = await (await fetch(`${BASE}/api/lab/shor`, { method: 'POST', headers: H, body: JSON.stringify({ N: 15 }) })).json();
check('lab N=15: recovered order r = 4', lab.r === 4);
check('lab N=15: factors are 3 and 5', lab.p === 3 && lab.q === 5);
check('lab N=15: recovered d decrypts toy ciphertext', lab.decryption_matches === true && lab.d === 7);
check('lab N=15: simulator is local Aer', /aer/i.test(lab.simulator));
check('lab N=15: 12 qubits (8 counting + 4 work)', lab.qubits.total === 12);
const lab2 = await (await fetch(`${BASE}/api/lab/shor`, { method: 'POST', headers: H, body: JSON.stringify({ N: 15 }) })).json();
check('lab N=15: repeat call served from cache', lab2.cached === true);
const lab21 = await (await fetch(`${BASE}/api/lab/shor`, { method: 'POST', headers: H, body: JSON.stringify({ N: 21 }) })).json();
check('lab N=21: r = 6, factors 3 and 7', lab21.r === 6 && lab21.p === 3 && lab21.q === 7 && lab21.decryption_matches === true);
const badN = await fetch(`${BASE}/api/lab/shor`, { method: 'POST', headers: H, body: JSON.stringify({ N: 35 }) });
check('lab: unsupported N rejected (400)', badN.status === 400);
const labUnauth = await fetch(`${BASE}/api/lab/shor`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
check('lab: unauthenticated request gets 401', labUnauth.status === 401);

console.log(`\n${passed} passed, ${failed} failed`);
await stopServer();
process.exit(failed ? 1 : 0);
