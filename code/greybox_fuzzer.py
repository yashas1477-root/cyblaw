"""
greybox_fuzzer.py
=================
Coverage-Based Greybox Fuzzing Seed Scheduler
Based on: Section IV.B – Equations 3 & 4 (THEME-16)

Implements the Markov-chain energy model by Böhme et al.:
  E(s) = α / ρ(p(s))          [Eq. 3]
  ρ(p) = |{s' ∈ S : p(s')=p}| / |S|   [Eq. 4]

The scheduler prioritises seeds that exercise low-density (rare) paths,
focusing fuzzing effort on unexplored certificate parsing edge cases.
"""

import hashlib
import random
import copy
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Set
from cert_generator import CertificateInput, CertMutantFactory


# ── Execution path simulation ──────────────────────────────────────────────────
def simulate_path(cert_data: bytes) -> str:
    """
    Simulate a code-coverage path ID for a certificate input.
    In a real fuzzer this would be an AFL-style bitmap hash.
    Here we use structural features of the cert bytes as a proxy.
    """
    features = []

    # Feature 1: outer SEQUENCE length bucket
    if len(cert_data) > 2:
        features.append(f"len_{len(cert_data) // 64}")

    # Feature 2: BER indefinite marker
    features.append("ber" if b"\x80\x00" in cert_data else "der")

    # Feature 3: null-byte in first 150 bytes
    features.append("nullbyte" if b"\x00" in cert_data[50:150] else "nonull")

    # Feature 4: high-bit INTEGER (negative serial)
    features.append("negserial" if (len(cert_data) > 6 and cert_data[6] & 0x80) else "posserial")

    # Feature 5: critical extension marker (BOOLEAN TRUE = 0xFF)
    features.append("critex" if b"\x01\x01\xff" in cert_data.lower() else "nocrit")

    return ":".join(features)


# ── Seed pool ──────────────────────────────────────────────────────────────────
@dataclass
class Seed:
    cert:     CertificateInput
    energy:   float = 1.0
    path_id:  str   = ""
    executions: int = 0
    bugs_found: int = 0

    def __post_init__(self):
        if not self.path_id:
            self.path_id = simulate_path(self.cert.data)


# ── Markov-chain energy model ──────────────────────────────────────────────────
class MarkovEnergyScheduler:
    """
    Implements Eq. 3 & 4 from THEME-16 Section IV.B.
    Seeds on rare execution paths receive higher energy (more mutations).
    """
    ALPHA = 100.0   # base energy constant (tunable)

    def __init__(self, seeds: List[Seed]):
        self.seeds = seeds
        self._update_densities()

    def _update_densities(self):
        """Recompute path densities ρ(p) across the current seed pool (Eq. 4)."""
        path_counts: Dict[str, int] = {}
        for s in self.seeds:
            path_counts[s.path_id] = path_counts.get(s.path_id, 0) + 1
        n = len(self.seeds)
        self._density: Dict[str, float] = {
            path: count / n for path, count in path_counts.items()
        }

    def assign_energy(self, seed: Seed) -> float:
        """E(s) = α / ρ(p(s))  [Eq. 3]"""
        rho = self._density.get(seed.path_id, 1.0 / max(len(self.seeds), 1))
        energy = self.ALPHA / rho
        seed.energy = min(energy, self.ALPHA * 10)   # cap to avoid runaway
        return seed.energy

    def select_seed(self) -> Seed:
        """
        Weighted selection: probability proportional to energy.
        Seeds on rare paths (high energy) are chosen more often.
        """
        self._update_densities()
        energies = [self.assign_energy(s) for s in self.seeds]
        total    = sum(energies)
        r        = random.uniform(0, total)
        cumul    = 0.0
        for seed, e in zip(self.seeds, energies):
            cumul += e
            if r <= cumul:
                return seed
        return self.seeds[-1]

    def add_seed(self, seed: Seed):
        """Add a newly discovered seed (new coverage path)."""
        self.seeds.append(seed)
        self._update_densities()

    def stats(self) -> Dict:
        self._update_densities()
        return {
            "total_seeds":   len(self.seeds),
            "unique_paths":  len(self._density),
            "path_densities": dict(sorted(self._density.items(),
                                          key=lambda x: x[1]))
        }


# ── Mutation operators ─────────────────────────────────────────────────────────
class CertMutator:
    """
    Byte-level mutation operators applied to certificate DER data.
    Mirrors the mutation strategies used by AFL/LibFuzzer on structured inputs.
    """
    @staticmethod
    def bit_flip(data: bytes, n_bits: int = 1) -> bytes:
        arr = bytearray(data)
        for _ in range(n_bits):
            idx = random.randint(0, len(arr) - 1)
            bit = 1 << random.randint(0, 7)
            arr[idx] ^= bit
        return bytes(arr)

    @staticmethod
    def byte_replace(data: bytes) -> bytes:
        arr = bytearray(data)
        idx = random.randint(0, len(arr) - 1)
        arr[idx] = random.randint(0, 255)
        return bytes(arr)

    @staticmethod
    def insert_bytes(data: bytes, n: int = 4) -> bytes:
        import os as _os2
        arr = bytearray(data)
        pos = random.randint(0, len(arr))
        arr[pos:pos] = _os2.urandom(n)
        return bytes(arr)

    @staticmethod
    def delete_bytes(data: bytes, n: int = 4) -> bytes:
        if len(data) <= n:
            return data
        arr = bytearray(data)
        pos = random.randint(0, len(arr) - n)
        del arr[pos:pos + n]
        return bytes(arr)

    @staticmethod
    def length_tamper(data: bytes) -> bytes:
        """Replace a length field with 0x00, 0x80 (BER indefinite), or oversized value."""
        arr = bytearray(data)
        # Find first length byte (simplified: byte index 1)
        if len(arr) > 2:
            arr[1] = random.choice([0x00, 0x80, 0xFF, 0x7F])
        return bytes(arr)

    @staticmethod
    def interesting_integer(data: bytes) -> bytes:
        """Replace an INTEGER value with edge-case values."""
        interesting = [b"\x00", b"\x01", b"\x7f", b"\x80", b"\xff",
                       b"\x00\x00", b"\xff\xff"]
        arr = bytearray(data)
        if len(arr) > 6:
            val = random.choice(interesting)
            arr[5:5 + len(val)] = val
        return bytes(arr)

    OPERATORS = [bit_flip.__func__, byte_replace.__func__, insert_bytes.__func__,
                 delete_bytes.__func__, length_tamper.__func__, interesting_integer.__func__]

    @classmethod
    def mutate(cls, data: bytes, num_mutations: int = 1) -> bytes:
        result = data
        for _ in range(num_mutations):
            op = random.choice(cls.OPERATORS)
            result = op(result)
        return result


def _has_os():
    try:
        import os; os.urandom(1); return True
    except Exception:
        return False


import os as _os


# ── Greybox Fuzzer ─────────────────────────────────────────────────────────────
class GreyboxFuzzer:
    """
    Full coverage-based greybox fuzzing loop.
    Integrates the Markov energy model with mutation operators.
    """
    def __init__(self, initial_corpus: List[CertificateInput],
                 oracle: Optional[Callable[[bytes], bool]] = None):
        """
        oracle: function(cert_bytes) → True if the cert triggers interesting behaviour.
                Defaults to a simulated path-coverage oracle.
        """
        self.seeds    = [Seed(c) for c in initial_corpus]
        self.scheduler = MarkovEnergyScheduler(self.seeds)
        self.oracle    = oracle or self._default_oracle
        self.visited_paths: Set[str] = {s.path_id for s in self.seeds}
        self.total_executions = 0
        self.new_coverage_found = 0

    @staticmethod
    def _default_oracle(cert_data: bytes) -> bool:
        """Returns True if the mutant exercises a new code path."""
        path = simulate_path(cert_data)
        return True   # always interesting for demo; real impl checks bitmap

    def fuzz_round(self, num_mutations: int = 10) -> List[CertificateInput]:
        """
        Execute one fuzzing round:
          1. Select a seed by energy
          2. Apply mutations
          3. Execute oracle
          4. If new coverage → add to corpus
        Returns list of newly discovered interesting inputs.
        """
        seed = self.scheduler.select_seed()
        seed.executions += 1
        new_finds: List[CertificateInput] = []

        # Number of mutations proportional to energy
        n_mutants = max(1, int(seed.energy / 20))

        for _ in range(n_mutants):
            mutant_data = CertMutator.mutate(seed.cert.data, num_mutations)
            self.total_executions += 1

            path = simulate_path(mutant_data)
            if path not in self.visited_paths:
                self.visited_paths.add(path)
                self.new_coverage_found += 1
                new_cert = CertificateInput(
                    cert_id=f"MUTANT-{self.total_executions:05d}",
                    data=mutant_data,
                    encoding="DER",
                    description=f"Mutant from {seed.cert.cert_id}",
                    tcev_category=seed.cert.tcev_category
                )
                new_seed = Seed(new_cert, path_id=path)
                self.scheduler.add_seed(new_seed)
                new_finds.append(new_cert)

        return new_finds

    def run(self, rounds: int = 50, verbose: bool = True) -> Dict:
        print(f"\n{'='*60}")
        print(f"  Greybox Fuzzer  –  {rounds} rounds")
        print(f"  Initial corpus : {len(self.seeds)} seeds")
        print(f"{'='*60}\n")

        all_finds: List[CertificateInput] = []

        for r in range(rounds):
            finds = self.fuzz_round()
            all_finds.extend(finds)
            if verbose and finds:
                print(f"  Round {r+1:3d}: {len(finds)} new path(s) discovered "
                      f"| corpus={len(self.scheduler.seeds)} "
                      f"| total_exec={self.total_executions}")

        stats = self.scheduler.stats()
        print(f"\n  Fuzzing complete.")
        print(f"  Total executions    : {self.total_executions}")
        print(f"  New paths found     : {self.new_coverage_found}")
        print(f"  Unique paths        : {stats['unique_paths']}")
        print(f"  Final corpus size   : {stats['total_seeds']}")

        return {
            "rounds":           rounds,
            "total_executions": self.total_executions,
            "new_paths":        self.new_coverage_found,
            "unique_paths":     stats["unique_paths"],
            "corpus_size":      stats["total_seeds"],
            "new_finds":        all_finds,
        }
