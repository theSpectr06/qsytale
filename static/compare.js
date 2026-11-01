import { runBenchmark } from './crypto.bundle.js?v=stage2';

const $ = (id) => document.getElementById(id);

const ms = (v) => `${v.toFixed(2)} ms`;
const bytes = (v) => `${v.toLocaleString()} B`;

const ROWS = [
    ['Keygen time (median)', 'keygenMs', ms],
    ['Public key size', 'publicKeyBytes', bytes],
    ['Private key size', 'privateKeyBytes', bytes],
    ['Per-file wrap data', 'wrapBytes', bytes],
    ['Wrap time, sender (median)', 'wrapMs', ms],
    ['Unwrap time, receiver (median)', 'unwrapMs', ms],
    ['Server key material, 2 devices, 1 file', 'serverBytes2Devices', bytes],
];

function cell(row, text, tag = 'td') {
    const c = document.createElement(tag);
    c.textContent = text;
    row.appendChild(c);
}

function render(r) {
    const table = $('table');
    table.replaceChildren();

    const head = document.createElement('tr');
    ['Metric', 'Classical (RSA-2048)', 'Post-quantum (ML-KEM-768)'].forEach((t) => cell(head, t, 'th'));
    table.appendChild(head);

    for (const [label, key, fmt] of ROWS) {
        const row = document.createElement('tr');
        cell(row, label);
        cell(row, fmt(r.rsa[key]));
        cell(row, fmt(r.mlkem[key]));
        table.appendChild(row);
    }
    table.parentElement.hidden = false;

    // Observations are generated from the measured numbers, not asserted.
    const faster = (a, b) => (a < b ? 'ML-KEM' : 'RSA');
    const parts = [
        `Keygen: ${faster(r.mlkem.keygenMs, r.rsa.keygenMs)} was faster here (${ms(r.mlkem.keygenMs)} vs ${ms(r.rsa.keygenMs)}).`,
        `Wrap: ${faster(r.mlkem.wrapMs, r.rsa.wrapMs)} was faster (${ms(r.mlkem.wrapMs)} vs ${ms(r.rsa.wrapMs)}).`,
        `Unwrap: ${faster(r.mlkem.unwrapMs, r.rsa.unwrapMs)} was faster (${ms(r.mlkem.unwrapMs)} vs ${ms(r.rsa.unwrapMs)}).`,
        `Sizes: ML-KEM public keys are ${(r.mlkem.publicKeyBytes / r.rsa.publicKeyBytes).toFixed(1)}x and per-file wraps ` +
        `${(r.mlkem.wrapBytes / r.rsa.wrapBytes).toFixed(1)}x the RSA sizes.`,
        `RSA keygen used ${r.rsaKeygenRuns} runs; other operations used ${r.iterations}. Browser timers may be coarse. ` +
        'This describes this device only and does not make one scheme "better".',
    ];
    $('observations').textContent = parts.join(' ');
}

$('run').addEventListener('click', async () => {
    try {
        $('run').disabled = true;
        const result = await runBenchmark({
            iterations: 20,
            rsaKeygenRuns: 5,
            onProgress: (m) => { $('log').textContent = m; },
        });
        render(result);
        $('log').textContent = `Done on: ${result.device}\n\n${JSON.stringify(result, null, 2)}`;
    } catch (error) {
        $('log').textContent = `BENCHMARK FAILED:\n${error.message}`;
    } finally {
        $('run').disabled = false;
    }
});
