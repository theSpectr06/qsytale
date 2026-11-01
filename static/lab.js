const $ = (id) => document.getElementById(id);
const token = localStorage.getItem('qsytale_token');

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}

function chip(text, className = 'chip') {
    return el('span', className, text);
}

function renderHero(r) {
    const hero = $('hero');
    hero.replaceChildren();
    hero.className = r.success ? 'hero' : 'hero warn';

    hero.append(el('div', 'eyebrow', r.success ? 'RSA key recovered' : 'No factors this run'));
    hero.append(el('div', 'equation', r.success ? `${r.N} = ${r.p} \u00d7 ${r.q}` : `N = ${r.N}`));
    hero.append(el('div', 'sub', r.success
        ? `e = ${r.e}  \u00b7  \u03c6 = ${r.phi}  \u00b7  d = ${r.d}`
        : 'No usable period this time. Run again.'));

    const chips = el('div', 'chips');
    ['Local Aer simulator', 'Ideal, no noise', 'Toy modulus'].forEach((t) => chips.append(chip(t)));
    if (r.cached) chips.append(chip('Cached result'));
    hero.append(chips);
}

function renderStats(r) {
    const stats = $('stats');
    stats.replaceChildren();
    const tiles = [
        ['Qubits', String(r.qubits.total), `${r.qubits.counting} counting + ${r.qubits.work} work`],
        ['Shots', String(r.shots), `${r.distinct_outcomes} distinct outcomes`],
        ['Order r', r.r === null ? 'none' : String(r.r), r.r === null ? 'no valid period' : `a^${r.r} \u2261 1 (mod ${r.N})`],
        ['Runtime', `${r.runtime_seconds.toFixed(2)} s`, r.cached ? 'from an earlier run' : 'this run'],
    ];
    for (const [k, v, s] of tiles) {
        const tile = el('div', 'tile');
        tile.append(el('div', 'k', k), el('div', 'v', v), el('div', 's', s));
        stats.append(tile);
    }
}

function renderHistogram(r) {
    const t = r.qubits.counting;

    const rows = [...r.outcomes].sort((a, b) => a.y - b.y);
    const max = Math.max(...rows.map((o) => o.count));
    const chart = $('histogram');
    chart.replaceChildren();

    for (const o of rows) {
        const col = el('div', o.y === 0 ? 'col zero' : 'col');
        col.append(el('div', 'val', String(o.count)));
        const plot = el('div', 'plot');
        const fill = el('div', 'fill');
        fill.style.height = `${Math.max(2, (o.count / max) * 100)}%`;  // CSSOM: allowed by CSP
        plot.append(fill);
        col.append(plot, el('div', 'x', String(o.y)), el('div', 'frac', `${o.y}/${2 ** t}`));
        chart.append(col);
    }
}

function digitRow(label, digits, ok = false) {
    const row = el('div', ok ? 'drow ok' : 'drow');
    row.append(el('div', 'lbl', label));
    const box = el('div', 'digits');
    digits.forEach((d) => box.append(el('span', '', String(d))));
    row.append(box);
    if (ok) row.append(el('span', 'match', 'Match'));
    return row;
}

function renderDecrypt(r) {
    const box = $('decrypt');
    box.replaceChildren();
    if (!r.success) {
        box.append(el('p', 'supporting', 'No key recovered.'));
        return;
    }
    box.append(
        digitRow('Plain', r.plaintext_digits),
        digitRow(`Encrypted (e = ${r.e})`, r.ciphertext_digits),
        digitRow(`Decrypted (d = ${r.d})`, r.decrypted_digits, r.decryption_matches),
    );
}

function render(r) {
    renderHero(r);
    renderStats(r);
    renderHistogram(r);
    renderDecrypt(r);

    const notes = $('notes');
    notes.replaceChildren();
    r.notes.forEach((n) => notes.append(el('li', '', n)));

    const gates = $('gates');
    gates.replaceChildren();
    Object.entries(r.gate_counts).forEach(([k, v]) => gates.append(chip(`${k} \u00d7${v}`)));
    $('circuit').textContent = r.circuit_text;

    $('result').hidden = false;
}

function setBusy(busy) {
    $('run').disabled = busy;
    $('run').textContent = busy ? 'Running\u2026' : 'Run Shor';
    $('progress').hidden = !busy;
}

function showError(message) {
    $('log').textContent = message;
    $('status').hidden = false;
}

async function runLab() {
    $('status').hidden = true;
    try {
        if (!token) throw new Error('This browser is not enrolled.');
        setBusy(true);

        const N = Number(document.querySelector('input[name="n"]:checked').value);
        const response = await fetch('/api/lab/shor', {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ N }),
        });

        if (!response.ok) {
            let detail = '';
            try { detail = (await response.json()).detail ?? ''; } catch { /* not JSON */ }
            throw new Error(`${response.status} ${detail}`);
        }

        render(await response.json());
    } catch (error) {
        showError(`LAB FAILED:\n${error.message}`);
    } finally {
        setBusy(false);
    }
}

$('run').addEventListener('click', runLab);
document.querySelectorAll('input[name="n"]').forEach((r) => r.addEventListener('change', runLab));
if (token) runLab();
