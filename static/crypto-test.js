import {
    generateDeviceKeys,
    unlockDevice,
    getStoredDevice
} from './crypto.bundle.js';

const output = document.getElementById('output');

document.getElementById('generate').addEventListener('click', async () => {
    try {
        output.textContent = 'Generating RSA-2048 and ML-KEM-768 keys...';

        const result = await generateDeviceKeys(
            document.getElementById('pass').value
        );

        output.textContent =
            `KEYS GENERATED\n` +
            `RSA public key: ${result.rsaPublicBytes} bytes\n` +
            `ML-KEM public key: ${result.mlkemPublicBytes} bytes\n` +
            `Private keys encrypted and saved in IndexedDB.`;
    } catch (error) {
        output.textContent = error.stack || error.message;
    }
});

document.getElementById('unlock').addEventListener('click', async () => {
    try {
        output.textContent = 'Unlocking...';

        const keys = await unlockDevice(
            document.getElementById('pass').value
        );

        output.textContent =
            `UNLOCK SUCCESSFUL\n` +
            `RSA private key: ${!!keys.rsaPrivate}\n` +
            `ML-KEM secret key: ${keys.mlkemSecret.length} bytes`;
    } catch (error) {
        output.textContent = error.stack || error.message;
    }
});

document.getElementById('enroll').addEventListener('click', async () => {
    try {
        output.textContent = 'Unlocking keys...';

        await unlockDevice(document.getElementById('pass').value);
        const device = await getStoredDevice();

        output.textContent = 'Sending public keys to server...';

        const response = await fetch('/api/enroll', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                invite_code: document.getElementById('invite').value.trim(),
                name: document.getElementById('device-name').value.trim(),
                rsa_pk: device.rsa_pk,
                mlkem_pk: device.mlkem_pk
            })
        });

        const result = await response.json();
        if (!response.ok) throw new Error(result.detail || 'Enrollment failed');

        localStorage.setItem('qsytale_token', result.token);
        localStorage.setItem('qsytale_device_id', result.device_id);

        output.textContent =
            `ENROLMENT SUCCESSFUL\nDevice ID: ${result.device_id}\nToken saved locally.`;
    } catch (error) {
        output.textContent = error.stack || error.message;
    }
});
