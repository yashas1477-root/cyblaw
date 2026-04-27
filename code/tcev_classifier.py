"""
tcev_classifier.py
==================
TCEV Taxonomy Classifier + CCR / BDR Metrics
Based on: Section V (Taxonomy) & Section VI (Comparison Matrix) – THEME-16

Implements:
  • Taxonomy of Certificate Exploit Vectors (TCEV) – 6 categories
  • Certificate Coverage Rate (CCR) calculation
  • Bug Discovery Rate (BDR) per 24-hour window
  • Comparison matrix scoring (mirrors Table III from the paper)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


# ── TCEV Taxonomy (Section V.B, Table II) ─────────────────────────────────────
TCEV_TAXONOMY = {
    "TCEV-1": {
        "name": "CA Trust Abuse",
        "description": "Exploitation of Certificate Authority trust relationships",
        "sub": {
            "TCEV-1.1": "Rogue CA certificate issuance",
            "TCEV-1.2": "OCSP responder spoofing",
            "TCEV-1.3": "Cross-CA trust path manipulation",
        }
    },
    "TCEV-2": {
        "name": "Parsing Logic Exploitation",
        "description": "ASN.1/DER parsing implementation bugs (most studied – 21 papers)",
        "sub": {
            "TCEV-2.1": "BER indefinite-length encoding abuse",
            "TCEV-2.2": "Null-byte injection in Subject/CN fields",
            "TCEV-2.3": "Negative or malformed serial number",
            "TCEV-2.4": "Zero-length mandatory fields",
            "TCEV-2.5": "Unrecognised critical extension bypass",
            "TCEV-2.6": "Inverted or anomalous validity window",
        }
    },
    "TCEV-3": {
        "name": "Chain Validation Bypass",
        "description": "Certificate chain construction and path validation bugs",
        "sub": {
            "TCEV-3.1": "Intermediate CA basic-constraints bypass",
            "TCEV-3.2": "Pathlen constraint violation",
            "TCEV-3.3": "Name constraints inconsistency",
        }
    },
    "TCEV-4": {
        "name": "Cryptographic Downgrade",
        "description": "Protocol/algorithm negotiation manipulation",
        "sub": {
            "TCEV-4.1": "Signature algorithm confusion (RSA/EC mismatch)",
            "TCEV-4.2": "Hash algorithm downgrade (SHA-1/MD5 fallback)",
            "TCEV-4.3": "TLS version rollback enabling legacy validators",
        }
    },
    "TCEV-5": {
        "name": "Revocation Bypass",
        "description": "Certificate revocation checking evasion",
        "sub": {
            "TCEV-5.1": "CRL staleness exploitation",
            "TCEV-5.2": "OCSP stapling manipulation",
            "TCEV-5.3": "Soft-fail revocation checking bypass",
        }
    },
    "TCEV-6": {
        "name": "Supply Chain Injection",
        "description": "Direct injection into software update pipelines (14 papers)",
        "sub": {
            "TCEV-6.1": "Package registry poisoning",
            "TCEV-6.2": "Code-signing certificate compromise",
            "TCEV-6.3": "Build system backdoor (e.g., XZ Utils CVE-2024-3094)",
            "TCEV-6.4": "SBOM integrity violation",
        }
    }
}


class TCEVClassifier:
    """
    Rule-based classifier that assigns a TCEV category to a certificate anomaly
    based on structural features of the DER bytes and observed validator behaviour.
    """

    @staticmethod
    def classify_bytes(cert_data: bytes) -> Tuple[str, str]:
        """
        Returns (tcev_code, description) for the most likely category.
        """
        # TCEV-2.1: BER indefinite length
        if b"\x80\x00" in cert_data:
            return "TCEV-2.1", "BER indefinite-length encoding detected"

        # TCEV-2.2: Null byte in first 200 bytes (CN region)
        if b"\x00" in cert_data[30:200]:
            return "TCEV-2.2", "Null-byte found in Subject/CN region"

        # TCEV-2.3: Negative serial (high bit of INTEGER value set)
        if len(cert_data) > 7 and cert_data[4] == 0x02 and cert_data[6] & 0x80:
            return "TCEV-2.3", "Negative serial number (missing 0x00 pad)"

        # TCEV-2.4: Zero-length SEQUENCE or SET
        if b"\x30\x00" in cert_data or b"\x31\x00" in cert_data:
            return "TCEV-2.4", "Zero-length SEQUENCE or SET field"

        # TCEV-2.5: Critical extension flag 0xFF
        if b"\x01\x01\xff" in cert_data:
            return "TCEV-2.5", "Critical extension marker present"

        # TCEV-4.2: MD5 OID present (1.2.840.113549.2.5)
        md5_oid_bytes = bytes([0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05])
        if md5_oid_bytes in cert_data:
            return "TCEV-4.2", "MD5 algorithm OID detected (hash downgrade)"

        return "UNKNOWN", "No specific TCEV pattern matched"

    @staticmethod
    def describe_category(code: str) -> Dict:
        cat = code.split(".")[0] if "." in code else code
        parent = TCEV_TAXONOMY.get(cat, {})
        sub_desc = ""
        for key in TCEV_TAXONOMY.get(cat, {}).get("sub", {}):
            if code == key:
                sub_desc = TCEV_TAXONOMY[cat]["sub"][key]
        return {
            "code":        code,
            "category":    parent.get("name", "Unknown"),
            "description": sub_desc or parent.get("description", ""),
            "parent":      cat,
        }

    def classify_divergence_event(self, cert_data: bytes,
                                  responses: Dict[str, str]) -> Dict:
        """Full classification of a divergence event."""
        tcev_code, reason = self.classify_bytes(cert_data)
        info = self.describe_category(tcev_code)

        # Determine attack phase from responses
        accept_count = sum(1 for r in responses.values() if r == "ACCEPT")
        reject_count = sum(1 for r in responses.values() if r == "REJECT")

        if accept_count > 0 and reject_count > 0:
            attack_phase = "ACTIVE_DIVERGENCE"   # can bypass strict validator
        elif "CRASH" in responses.values():
            attack_phase = "DENIAL_OF_SERVICE"
        else:
            attack_phase = "UNIFORM_REJECT"

        return {
            **info,
            "reason":       reason,
            "attack_phase": attack_phase,
            "responses":    responses,
        }


# ── CCR & BDR Metrics (Section VI, Table III) ─────────────────────────────────
@dataclass
class FuzzerBenchmark:
    """
    Mirrors a row in Table III of the paper.
    CCR = Certificate Coverage Rate (%)
    BDR = Bug Discovery Rate (bugs / 24h)
    JDR = Jaccard Distance Range [min, max]
    """
    name:     str
    ccr:      float          # 0–100 %
    bdr_24h:  float          # bugs per 24 hours
    jdr_min:  float
    jdr_max:  float
    overhead: str            # Low | Medium | High

    @property
    def jdr_range(self) -> str:
        return f"[{self.jdr_min:.2f}, {self.jdr_max:.2f}]"

    @property
    def security_tier(self) -> str:
        if self.ccr >= 88:
            return "TIER-1 (Deep Stateful)"
        elif self.ccr >= 70:
            return "TIER-2 (Stateful)"
        else:
            return "TIER-3 (Shallow)"


# Recreates the comparison matrix from Table III of THEME-16
FUZZER_BENCHMARK_TABLE: List[FuzzerBenchmark] = [
    FuzzerBenchmark("TLS-DeepDiffer",      91.2, 6.1,  0.68, 0.81, "High"),
    FuzzerBenchmark("S2Fuzzer",            89.7, 5.8,  0.71, 0.79, "High"),
    FuzzerBenchmark("AcSelector",          88.4, 5.4,  0.65, 0.78, "Medium"),
    FuzzerBenchmark("AFLNet",              76.3, 3.9,  0.48, 0.63, "Medium"),
    FuzzerBenchmark("AFLNET+stateful",     78.1, 4.1,  0.50, 0.65, "Medium"),
    FuzzerBenchmark("NEZHA",               72.5, 3.5,  0.41, 0.57, "Medium"),
    FuzzerBenchmark("TLS-Anvil",           74.8, 3.7,  0.44, 0.60, "Medium"),
    FuzzerBenchmark("Superion",            65.2, 2.8,  0.31, 0.48, "Low"),
    FuzzerBenchmark("MundoFuzz",           63.7, 2.5,  0.28, 0.44, "Low"),
    FuzzerBenchmark("LibFuzzer-baseline",  58.4, 2.1,  0.22, 0.38, "Low"),
    FuzzerBenchmark("AFL++",               61.9, 2.4,  0.25, 0.41, "Low"),
    FuzzerBenchmark("VCDFuzz",             80.3, 4.4,  0.52, 0.67, "Medium"),
    FuzzerBenchmark("FIRM-COV",            55.8, 1.9,  0.19, 0.34, "Low"),
    FuzzerBenchmark("RumFuzz",             67.4, 2.9,  0.33, 0.49, "Low"),
    FuzzerBenchmark("LinFuzz",             69.1, 3.1,  0.35, 0.52, "Medium"),
]


class MetricsCalculator:
    """
    Compute CCR and BDR from a live fuzzing run.
    """
    # Total RFC 5280 MUST/SHOULD conformance requirements (from paper)
    RFC5280_TOTAL_REQUIREMENTS = 93

    def __init__(self):
        self.tested_requirements: set = set()
        self.bugs_found: List[Dict] = []
        self.start_time: Optional[float] = None

    def record_requirement_covered(self, req_id: str):
        """Mark an RFC 5280 requirement as covered by the fuzzer."""
        self.tested_requirements.add(req_id)

    def record_bug(self, bug_info: Dict):
        """Log a discovered divergence as a bug."""
        import time
        bug_info["timestamp"] = time.time()
        self.bugs_found.append(bug_info)

    def start_timer(self):
        import time
        self.start_time = time.time()

    def ccr(self) -> float:
        """Certificate Coverage Rate = covered / total RFC 5280 requirements."""
        return len(self.tested_requirements) / self.RFC5280_TOTAL_REQUIREMENTS * 100

    def bdr(self) -> float:
        """Bug Discovery Rate = bugs found per 24-hour equivalent."""
        if not self.start_time or not self.bugs_found:
            return 0.0
        import time
        elapsed_hours = (time.time() - self.start_time) / 3600
        if elapsed_hours < 0.0001:
            return float(len(self.bugs_found))
        return len(self.bugs_found) / elapsed_hours * 24

    def print_comparison(self):
        """Print the benchmark comparison table (Table III from paper)."""
        print(f"\n{'='*75}")
        print(f"  FUZZER COMPARISON MATRIX (from THEME-16 Table III)")
        print(f"{'='*75}")
        print(f"  {'Tool':<22} {'CCR%':>6} {'BDR/24h':>8} {'JDR Range':>16} {'Overhead':<8} {'Tier'}")
        print(f"  {'-'*22} {'-'*6} {'-'*8} {'-'*16} {'-'*8} {'-'*20}")
        for fb in sorted(FUZZER_BENCHMARK_TABLE, key=lambda x: -x.ccr):
            print(f"  {fb.name:<22} {fb.ccr:>5.1f}% {fb.bdr_24h:>7.1f}  "
                  f"{fb.jdr_range:>16}  {fb.overhead:<8} {fb.security_tier}")
        print(f"{'='*75}")
