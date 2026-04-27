"""
differential_fuzzer.py
======================
Differential Fuzzing Engine for X.509 Certificate Parsing
Based on: Supply Chain Integrity and Software Piracy: A Review of
Fuzzing-Driven X.509 Certificate Vulnerabilities (THEME-16)

Core implementation of Equation 1 & 2 from Section IV:
  Objective: max |{R(I_k, c*) : k in [n]}|
  Constraint: exist I_j, I_k : R(I_j, c*) != R(I_k, c*)
"""

import subprocess
import hashlib
import os
import tempfile
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


# ── Response types (Eq. 1 domain) ─────────────────────────────────────────────
class ValidatorResponse(str, Enum):
    ACCEPT  = "ACCEPT"
    REJECT  = "REJECT"
    CRASH   = "CRASH"
    TIMEOUT = "TIMEOUT"
    ERROR   = "ERROR"


# ── Data structures ────────────────────────────────────────────────────────────
@dataclass
class CertificateInput:
    """A single test certificate input (PEM or DER bytes)."""
    cert_id:    str
    data:       bytes
    encoding:   str = "DER"   # DER | BER | PEM
    description: str = ""
    tcev_category: str = ""   # TCEV-1 … TCEV-6


@dataclass
class ValidationResult:
    validator:  str
    response:   ValidatorResponse
    detail:     str = ""
    latency_ms: float = 0.0


@dataclass
class DivergenceEvent:
    cert_id:    str
    responses:  Dict[str, ValidatorResponse]
    is_divergent: bool = False
    jaccard_distance: float = 0.0
    tcev_hint:  str = ""

    def summary(self) -> str:
        lines = [f"[{'DIVERGENT' if self.is_divergent else 'UNIFORM'}] cert={self.cert_id}"]
        for v, r in self.responses.items():
            lines.append(f"  {v:20s} → {r.value}")
        lines.append(f"  Jaccard Distance = {self.jaccard_distance:.4f}")
        if self.tcev_hint:
            lines.append(f"  TCEV Category    = {self.tcev_hint}")
        return "\n".join(lines)


# ── Validator wrappers ─────────────────────────────────────────────────────────
class CertificateValidator:
    """
    Thin wrapper around a command-line certificate validator.
    Subclass or configure `cmd_template` for each tool.
    """
    def __init__(self, name: str, cmd_template: List[str], timeout: float = 5.0):
        self.name = name
        self.cmd_template = cmd_template   # use {cert_file} as placeholder
        self.timeout = timeout

    def validate(self, cert_data: bytes) -> ValidationResult:
        t0 = time.perf_counter()
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
            f.write(cert_data)
            cert_path = f.name
        try:
            cmd = [c.replace("{cert_file}", cert_path) for c in self.cmd_template]
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout
            )
            elapsed = (time.perf_counter() - t0) * 1000
            if result.returncode == 0:
                return ValidationResult(self.name, ValidatorResponse.ACCEPT,
                                        result.stdout.decode(errors="replace"), elapsed)
            else:
                stderr = result.stderr.decode(errors="replace")
                return ValidationResult(self.name, ValidatorResponse.REJECT, stderr, elapsed)
        except subprocess.TimeoutExpired:
            return ValidationResult(self.name, ValidatorResponse.TIMEOUT,
                                    "Process timed out", self.timeout * 1000)
        except Exception as e:
            return ValidationResult(self.name, ValidatorResponse.ERROR, str(e), 0)
        finally:
            os.unlink(cert_path)


class SimulatedValidator:
    """
    Pure-Python simulated validator for environments without OpenSSL binaries.
    Applies rule-based accept/reject logic to reproduce known divergence patterns.
    """
    def __init__(self, name: str, quirks: Optional[List[str]] = None):
        self.name = name
        self.quirks = quirks or []   # e.g. ["accept_negative_serial", "ignore_null_byte"]

    def validate(self, cert_data: bytes) -> ValidationResult:
        t0 = time.perf_counter()
        # Heuristic checks (mirrors real-world parser divergence from the literature)
        issues = []

        # Null-byte in CN (TCEV-2.2)
        if b"\x00" in cert_data[50:100]:
            issues.append("null_byte_cn")

        # Non-DER BER encoding marker (TCEV-2.1) – BER allows indefinite length 0x80
        if b"\x80\x00" in cert_data:
            issues.append("ber_indefinite_length")

        # Negative serial (TCEV-2.3) – ASN.1 INTEGER with high bit set w/o 0x00 pad
        if len(cert_data) > 10 and cert_data[4] == 0x02 and cert_data[6] & 0x80:
            issues.append("negative_serial")

        # Zero-length field (TCEV-2.4)
        if b"\x04\x00" in cert_data or b"\x13\x00" in cert_data:
            issues.append("zero_length_field")

        elapsed = (time.perf_counter() - t0) * 1000

        # Apply quirk overrides
        for issue in issues:
            if issue not in self.quirks:
                return ValidationResult(self.name, ValidatorResponse.REJECT,
                                        f"Rejected: {issue}", elapsed)

        return ValidationResult(self.name, ValidatorResponse.ACCEPT, "OK", elapsed)


# ── Jaccard Distance (Equation 5 & 6) ─────────────────────────────────────────
class JaccardMetric:
    """
    Tracks acceptance sets A_j, A_k per validator and computes:
      J(I_j, I_k)   = |A_j ∩ A_k| / |A_j ∪ A_k|
      D_J(I_j, I_k) = 1 - J  =  |A_j Δ A_k| / |A_j ∪ A_k|
    """
    def __init__(self):
        self.acceptance_sets: Dict[str, set] = {}

    def record(self, cert_id: str, validator: str, response: ValidatorResponse):
        if validator not in self.acceptance_sets:
            self.acceptance_sets[validator] = set()
        if response == ValidatorResponse.ACCEPT:
            self.acceptance_sets[validator].add(cert_id)

    def jaccard_similarity(self, v1: str, v2: str) -> float:
        a1 = self.acceptance_sets.get(v1, set())
        a2 = self.acceptance_sets.get(v2, set())
        union = a1 | a2
        if not union:
            return 1.0
        return len(a1 & a2) / len(union)

    def jaccard_distance(self, v1: str, v2: str) -> float:
        return 1.0 - self.jaccard_similarity(v1, v2)

    def pairwise_distances(self) -> Dict[Tuple[str, str], float]:
        validators = list(self.acceptance_sets.keys())
        result = {}
        for i in range(len(validators)):
            for j in range(i + 1, len(validators)):
                pair = (validators[i], validators[j])
                result[pair] = self.jaccard_distance(*pair)
        return result

    def security_level(self, v1: str, v2: str) -> str:
        """
        Threshold classification from Section IV.C:
          D_J ∈ [0.00, 0.35] → low divergence  (shallow fuzzer territory)
          D_J ∈ [0.35, 0.50] → moderate
          D_J ∈ [0.50, 1.00] → high (deep stateful fuzzer territory, exploitable)
        """
        dj = self.jaccard_distance(v1, v2)
        if dj < 0.35:
            return f"LOW    (D_J={dj:.3f}) – minor parsing inconsistency"
        elif dj < 0.50:
            return f"MEDIUM (D_J={dj:.3f}) – decision boundary"
        else:
            return f"HIGH   (D_J={dj:.3f}) – systematically exploitable gap"


# ── Differential Fuzzing Engine ────────────────────────────────────────────────
class DifferentialFuzzingEngine:
    """
    Core engine implementing Equations 1–2.
    Feeds the same certificate inputs to all registered validators,
    records responses, and surfaces divergence events.
    """
    def __init__(self):
        self.validators: List = []
        self.jaccard = JaccardMetric()
        self.events: List[DivergenceEvent] = []

    def add_validator(self, validator):
        self.validators.append(validator)

    def run(self, cert_inputs: List[CertificateInput]) -> List[DivergenceEvent]:
        print(f"\n{'='*60}")
        print(f"  Differential Fuzzing Engine  –  {len(self.validators)} validators")
        print(f"  Corpus size: {len(cert_inputs)} certificates")
        print(f"{'='*60}\n")

        for cert in cert_inputs:
            responses: Dict[str, ValidatorResponse] = {}

            for v in self.validators:
                result = v.validate(cert.data)
                responses[v.name] = result.response
                self.jaccard.record(cert.cert_id, v.name, result.response)

            # Check for divergence (Eq. 2)
            unique_responses = set(responses.values())
            is_divergent = len(unique_responses) > 1

            # Compute pairwise D_J for this cert's response vector
            names = list(responses.keys())
            dj = 0.0
            if len(names) >= 2:
                # Symmetric divergence score for this single input
                agree = sum(1 for i in range(len(names))
                            for j in range(i+1, len(names))
                            if responses[names[i]] == responses[names[j]])
                total_pairs = len(names) * (len(names) - 1) // 2
                dj = 1.0 - (agree / total_pairs) if total_pairs else 0.0

            event = DivergenceEvent(
                cert_id=cert.cert_id,
                responses=responses,
                is_divergent=is_divergent,
                jaccard_distance=dj,
                tcev_hint=cert.tcev_category
            )
            self.events.append(event)

            if is_divergent:
                print(event.summary())
                print()

        return self.events

    def report(self) -> Dict:
        divergent = [e for e in self.events if e.is_divergent]
        total = len(self.events)
        bdr = len(divergent)   # Bug Discovery Rate (bugs per corpus)

        print(f"\n{'='*60}")
        print(f"  FUZZING REPORT")
        print(f"{'='*60}")
        print(f"  Total certificates tested : {total}")
        print(f"  Divergence events (BDR)   : {bdr}")
        print(f"  Divergence rate           : {bdr/total*100:.1f}%" if total else "  N/A")

        print(f"\n  Pairwise Jaccard Distances:")
        for (v1, v2), dj in self.jaccard.pairwise_distances().items():
            level = self.jaccard.security_level(v1, v2)
            print(f"    {v1} ↔ {v2}: {level}")

        tcev_counts: Dict[str, int] = {}
        for e in divergent:
            cat = e.tcev_hint or "UNKNOWN"
            tcev_counts[cat] = tcev_counts.get(cat, 0) + 1

        if tcev_counts:
            print(f"\n  TCEV Category Breakdown:")
            for cat, count in sorted(tcev_counts.items()):
                print(f"    {cat}: {count} divergence(s)")

        return {
            "total": total,
            "divergent": bdr,
            "pairwise_dj": {f"{v1}|{v2}": dj
                            for (v1, v2), dj in self.jaccard.pairwise_distances().items()},
            "tcev": tcev_counts
        }
