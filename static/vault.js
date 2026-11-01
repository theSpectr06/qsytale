import {
    unlockDevice,
    uploadFileClassical,
    listVault,
    downloadFile,
    MAX_FILE_SIZE,
} from './crypto.bundle.js?v=stage1';

const $ = (id) => document.getElementById(id);
const log = $('log');

const token = localStorage.getItem('qsytale_token');
const deviceId = localStorage.getItem('qsytale_device_id');
const ctx = { token, baseUrl: '' };

let keys = null;
let items = [];

function say(message) {
    log.textContent = message;
}

function saveBytes(bytes, name, type) {
    const blob = new Blob([bytes], { type: type || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = name || 'download.bin';
    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}

function renderFiles() {
    const list = $('files');
    list.replaceChildren();

    if (items.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No files yet.';
        list.appendChild(li);
        return;
    }

    for (const item of items) {
        const li = document.createElement('li');

        const title = document.createElement('div');
        title.textContent = item.error ? '(unreadable file)' : item.name;
        li.appendChild(title);

        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = item.mode;
        li.appendChild(badge);

        const meta = document.createElement('div');
        meta.className = 'meta';
        meta.textContent = item.error
            ? item.error
            : `${formatSize(item.size)} | from ${item.uploader.slice(0, 8)} | ${item.created.slice(0, 19)}`;
        if (item.error) meta.classList.add('error');
        li.appendChild(meta);

        if (!item.error) {
            const button = document.createElement('button');
            button.textContent = 'Download and decrypt';
            button.addEventListener('click', () => handleDownload(item));
            li.appendChild(button);
        }

        list.appendChild(li);
    }
}

async function refresh() {
    say('Loading file list and unwrapping keys...');
    items = await listVault(ctx, keys.rsaPrivate);
    renderFiles();
    say(`${items.length} file(s) in the vault.`);
}

async function handleDownload(item) {
    try {
        say(`Downloading and decrypting ${item.name}...`);
        const start = performance.now();

        const result = await downloadFile(ctx, item);
        const ms = (performance.now() - start).toFixed(0);

        saveBytes(result.bytes, result.name, result.type);

        say(
            `DOWNLOAD OK: ${result.name}\n` +
            `Recovered ${result.bytes.length} bytes in ${ms} ms\n` +
            `SHA-256 of recovered file:\n${result.sha256}`
        );
    } catch (error) {
        say(`DOWNLOAD FAILED:\n${error.message}`);
    }
}

$('unlock').addEventListener('click', async () => {
    try {
        say('Unlocking (scrypt may take a few seconds)...');
        keys = await unlockDevice($('pass').value);

        $('pass').value = '';
        $('unlock-section').hidden = true;
        $('vault-section').hidden = false;

        await refresh();
    } catch (error) {
        keys = null;
        say(`UNLOCK FAILED:\n${error.message}`);
    }
});

$('upload').addEventListener('click', async () => {
    try {
        const file = $('file').files[0];

        if (!file) throw new Error('Choose a file first.');
        if (file.size > MAX_FILE_SIZE) throw new Error('File exceeds 20 MiB.');

        say(`Encrypting ${file.name} (${formatSize(file.size)})...`);
        const start = performance.now();

        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = await uploadFileClassical(ctx, {
            bytes,
            name: file.name,
            type: file.type,
        });

        const ms = (performance.now() - start).toFixed(0);

        await refresh();

        say(
            `UPLOAD OK: ${file.name}\n` +
            `Encrypted, wrapped for ${result.wrappedFor} device(s), ` +
            `stored ${result.storedBytes} bytes in ${ms} ms\n` +
            `SHA-256 of original file:\n${result.plaintextSha256}`
        );
    } catch (error) {
        say(`UPLOAD FAILED:\n${error.message}`);
    }
});

$('refresh').addEventListener('click', async () => {
    try {
        await refresh();
    } catch (error) {
        say(`REFRESH FAILED:\n${error.message}`);
    }
});

if (!token || !deviceId) {
    $('whoami').textContent = 'This browser is not enrolled. Use the enrolment page first.';
    $('unlock').disabled = true;
} else {
    $('whoami').textContent = `Device ${deviceId}`;
}
