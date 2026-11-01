# Qsytale

Quantum Hack Day Kochi, Challenge 5 (Post-Quantum Cryptography).

A two-device encrypted file vault with two key-wrapping modes, **classical (RSA-2048)** and **post-quantum (ML-KEM-768)**, plus a **Quantum Attack Lab** that runs Shor's algorithm on a local Qiskit Aer simulator against a toy RSA key, and a **Compare** page that benchmarks both schemes on the device you open it on.

> Team / members / roles: _fill in before submission_.

## Problem and solution

RSA protects key exchange for most file sharing today. A large fault-tolerant quantum computer running Shor's algorithm would break it, and data recorded now can be decrypted later ("harvest now, decrypt later"). Qsytale shows that file sharing can move to a post-quantum key-encapsulation mechanism without changing how users interact with it.

**Input -> Processing -> Output**

1. Input: a file chosen in the browser, and a mode (classical or post-quantum).
2. Processing, all in the browser: random 32-byte file key (FEK); file encrypted with AES-256-GCM; the FEK wrapped separately for every enrolled device (RSA-OAEP, or ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM).
3. Output: the server stores only the ciphertext, the wrapped keys and public keys. Another enrolled device downloads, unwraps its own key and decrypts.

```
 Browser (laptop)              FastAPI server              Browser (phone)
 AES-GCM encrypt file  ---->   ciphertext blob     <----   unwrap own FEK, decrypt
 wrap FEK per device           wrapped keys                private keys in IndexedDB
 private keys in IndexedDB     public keys + metadata      (scrypt + AES-GCM protected)
                               Qiskit Shor lab (Python, local Aer)
```

## Cryptographic design

| Mode | Wrap of the FEK for one device |
| --- | --- |
| Classical | RSA-OAEP (SHA-256, MGF1-SHA-256) under the device's RSA-2048 public key (256 B) |
| Post-quantum | `(kem_ct, ss) = ML-KEM-768.Encaps(pk)`; `k = HKDF-SHA-256(ss, info = "qsytale/v1/mlkem-wrap/<file_id>/<device_id>")`; `wrapped = AES-256-GCM(k, wnonce, FEK, aad = "qsytale/v1/mlkem-wrap-aad/<file_id>/<device_id>")` (1088 + 12 + 48 B) |

File content and the encrypted name/type/size record use AES-256-GCM under the FEK with the file id bound as AAD. The wrap algorithm is stored with each wrap, so older classical files keep working next to post-quantum ones.

## Quantum component (Qiskit)

- Libraries: `qiskit`, `qiskit-aer` (`AerSimulator`). Nothing else; no IBM Quantum API, cloud, or hardware.
- Algorithm: Shor's period finding. The controlled modular multiplications `|x> -> |a^(2^k) x mod N>` are built directly as permutation unitaries (`shor_lab.py`), followed by an inverse QFT on the counting register (`2n` counting qubits, `n` work qubits).
- Classical pre/post-processing around one quantum subroutine: choose `a`; after measurement, continued fractions give the order `r`; `gcd(a^(r/2) +/- 1, N)` gives the factors; the toy RSA private exponent `d` is then recomputed and used to decrypt sample digits.
- Verified on Aer: N = 15 (a = 7, 12 qubits) peaks at y = 0, 64, 128, 192, r = 4, factors 3 x 5; N = 21 (a = 2, 15 qubits) gives r = 6, factors 3 x 7.

## Setup and run

```
uv sync
npm install
npx esbuild static/crypto.src.js --bundle --format=esm --minify --outfile=static/crypto.bundle.js
uv run uvicorn server:app --host 10.8.0.1 --port 8443 \
  --ssl-keyfile 10.8.0.1-key.pem --ssl-certfile 10.8.0.1.pem
```

Pages: `/static/vault.html`, `/static/lab.html`, `/static/compare.html`. The server prints a one-use enrolment invite at startup. Network (WireGuard `10.8.0.1` / `10.8.0.2`) and mkcert certificates are set up outside this repo and are not committed.

## Tests

```
uv run python -m unittest tests.test_shor_lab -v   # Shor lab (Aer)
./tests/run_e2e.sh                                 # real server + two simulated devices, throwaway database
```

The end-to-end test sets `QSYTALE_DATA_DIR` to a temporary directory, so it never touches `data/`.

## Third-party code

FastAPI, Uvicorn, python-multipart, NumPy, Qiskit and Qiskit Aer; `@noble/post-quantum` (ML-KEM), `@noble/ciphers` (AES-GCM), `@noble/hashes` (HKDF, scrypt, SHA-256), `node-forge` (RSA); esbuild; WireGuard; mkcert.

## Limitations (please read)

- The Shor lab is an ideal classical simulation with a hand-built circuit for a 4 or 5-bit modulus. N = 15 and 21 factor instantly by trial division; the lab shows the mechanism, not an advantage.
- Resource estimate for the real threat: Gidney, "How to factor 2048 bit RSA integers with less than a million noisy qubits" (arXiv:2505.15917, 2025). Current machines are far smaller. Later preprints claim lower figures; check primary sources before quoting them.
- ML-KEM security rests on lattice problems (module-LWE); no efficient quantum algorithm is known, which is not a proof of security.
- A device enrolled after an upload has no wrap for older files (no re-wrapping or approval flow).
- Server-delivered JavaScript is trusted: a malicious server could ship bad crypto code. Public keys are authenticated only by manual fingerprint comparison.
- Pure-JS crypto is unaudited and not constant-time. No token revocation. Not production software.
- Benchmark numbers describe the device and browser they were measured on, not the schemes in general.

## Future work

Device approval and re-wrapping, hybrid RSA + ML-KEM mode, ML-DSA signatures, a real-hardware N = 15 run.
