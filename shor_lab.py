"""Qsytale Quantum Attack Lab: Shor's algorithm on a local Qiskit Aer simulator.

Everything here runs locally. There is no IBM Quantum API, no cloud execution
and no real quantum hardware. The circuit is hand-built for a 4 or 5-bit
modulus; it demonstrates the mechanism of the attack, not a quantum advantage.
"""

import time
from fractions import Fraction
from math import gcd

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFTGate, UnitaryGate
from qiskit_aer import AerSimulator

# N -> (base a, toy RSA public exponent e). Both choices are coprime as required.
PARAMS = {
    15: {"a": 7, "e": 7},   # order 4, phi = 8
    21: {"a": 2, "e": 5},   # order 6, phi = 12
}

TOY_PLAINTEXT_DIGITS = [1, 0, 3, 1]  # the digits of "1031"

NOTES = [
    "This runs on a classical simulator (Qiskit Aer), not quantum hardware, "
    "and the circuit is hand-built for a 4 or 5-bit modulus.",
    "N = 15 and N = 21 can be factored by trial division instantly. The lab shows "
    "the mechanism of Shor's algorithm, not a speed advantage.",
    "Published estimates (Gidney 2025, arXiv:2505.15917) put factoring RSA-2048 "
    "at under one million noisy physical qubits and under a week, under stated "
    "hardware assumptions. Today's machines are far smaller, but estimates keep "
    "falling, which is why migration planning starts now.",
    "Shor's algorithm exploits the hidden periodic structure of modular "
    "exponentiation. ML-KEM's security rests on lattice problems (module-LWE), "
    "for which no efficient quantum algorithm is known. That is not a proof of "
    "security.",
    "Harvest-now-decrypt-later is the reason to migrate early: data encrypted "
    "today can be recorded and attacked later.",
    "Toy RSA digits 0 and 1 encrypt to themselves for any key; they are shown "
    "only because the demo plaintext is \"1031\".",
]


def ctrl_mulmod(a, N, n):
    """Controlled multiplication by a mod N, built directly as a permutation.

    Acts on n + 1 qubits. The control is the most significant qubit, so the
    gate is appended with the n work qubits first and the control last.
    Basis states with x >= N are left unchanged (the map must stay a permutation).
    """
    dim = 2 ** n
    U = np.zeros((2 * dim, 2 * dim))
    for c in (0, 1):
        for x in range(dim):
            y = (a * x) % N if (c == 1 and x < N) else x
            U[y + c * dim, x + c * dim] = 1
    return UnitaryGate(U)


def build_circuit(a, N):
    n = N.bit_length()
    t = 2 * n
    qc = QuantumCircuit(t + n, t)
    qc.h(range(t))
    qc.x(t)  # work register starts in |1>
    for k in range(t):
        qc.append(
            ctrl_mulmod(pow(a, 2 ** k, N), N, n),
            [*range(t, t + n), k],
        )
    qc.append(QFTGate(t).inverse(), range(t))
    qc.measure(range(t), range(t))
    return qc, n, t


def candidate_orders(y, t, a, N):
    """Order candidates from one measurement y via continued fractions."""
    if y == 0:
        return []  # y = 0 carries no information
    denom = Fraction(y, 2 ** t).limit_denominator(N).denominator
    found = []
    for m in range(1, N // denom + 1):
        r = denom * m
        if pow(a, r, N) == 1:
            found.append(r)
            break  # smallest valid multiple
    return found


def recover_order(counts, t, a, N):
    votes = {}
    per_outcome = []
    for bits, count in counts.items():
        y = int(bits, 2)
        cands = candidate_orders(y, t, a, N)
        per_outcome.append(
            {
                "y": y,
                "count": count,
                "phase": y / 2 ** t,
                "r_candidate": cands[0] if cands else None,
            }
        )
        for r in cands:
            votes[r] = votes.get(r, 0) + count
    per_outcome.sort(key=lambda d: -d["count"])
    if not votes:
        return None, per_outcome
    best = max(votes.items(), key=lambda kv: (kv[1], -kv[0]))[0]
    return best, per_outcome


def factors_from_order(a, r, N):
    if r is None or r % 2 != 0:
        return None
    x = pow(a, r // 2, N)
    if x == N - 1:
        return None
    p, q = gcd(x - 1, N), gcd(x + 1, N)
    for f in (p, q):
        if 1 < f < N:
            return sorted((f, N // f))
    return None


def run_shor(N=15, shots=1024):
    if N not in PARAMS:
        raise ValueError(f"N must be one of {sorted(PARAMS)}")
    a, e = PARAMS[N]["a"], PARAMS[N]["e"]
    started = time.perf_counter()

    qc, n, t = build_circuit(a, N)
    sim = AerSimulator()
    compiled = transpile(qc, sim)
    counts = sim.run(compiled, shots=shots).result().get_counts()

    r, per_outcome = recover_order(counts, t, a, N)
    pq = factors_from_order(a, r, N)

    result = {
        "N": N,
        "a": a,
        "e": e,
        "simulator": "qiskit-aer AerSimulator (local, ideal, no noise)",
        "shots": shots,
        "qubits": {"counting": t, "work": n, "total": t + n},
        "gate_counts": {k: int(v) for k, v in qc.count_ops().items()},
        "histogram": [
            {"y": d["y"], "count": d["count"]} for d in per_outcome[:12]
        ],
        "outcomes": per_outcome[:12],
        "distinct_outcomes": len(per_outcome),
        "r": r,
        "success": pq is not None,
        "notes": NOTES,
        "circuit_text": str(qc.draw("text", fold=120)),
    }

    if pq:
        p, q = pq
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        cipher = [pow(m, e, N) for m in TOY_PLAINTEXT_DIGITS]
        plain = [pow(c, d, N) for c in cipher]
        result.update(
            {
                "p": p,
                "q": q,
                "phi": phi,
                "d": d,
                "plaintext_digits": TOY_PLAINTEXT_DIGITS,
                "ciphertext_digits": cipher,
                "decrypted_digits": plain,
                "decryption_matches": plain == TOY_PLAINTEXT_DIGITS,
            }
        )

    result["runtime_seconds"] = round(time.perf_counter() - started, 3)
    return result
