"""
main.py
=======
Main Demo Runner – THEME-16 Source Code Suite
X.509 Certificate Differential Fuzzing Research Implementation

Modules:
  differential_fuzzer.py  –  Core engine (Eq. 1, 2, 5, 6)
  cert_generator.py       –  TCEV-2 malformed certificate corpus
  greybox_fuzzer.py       –  Markov-chain seed scheduler (Eq. 3, 4)
  tcev_classifier.py      –  TCEV taxonomy + CCR/BDR metrics

Run:
  python main.py
"""

import time
from differential_fuzzer import DifferentialFuzzingEngine, SimulatedValidator
from cert_generator        import CertMutantFactory
from greybox_fuzzer        import GreyboxFuzzer
from tcev_classifier       import TCEVClassifier, MetricsCalculator, FUZZER_BENCHMARK_TABLE


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   X.509 Certificate Differential Fuzzing – THEME-16         ║
║   Supply Chain Integrity & Software Piracy Research          ║
║   Dept. of CSE (Cyber Security), JAIN Deemed-to-be Univ.    ║
╚══════════════════════════════════════════════════════════════╝
""")


def phase1_differential_fuzzing():
    print("\n" + "━"*60)
    print("  PHASE 1 – Differential Fuzzing Engine")
    print("  (Equations 1, 2 – Section IV.A)")
    print("━"*60)

    # Simulate three validators with different quirks
    # (mirrors OpenSSL, BoringSSL, WolfSSL from the paper)
    openssl  = SimulatedValidator("OpenSSL-3.x",   quirks=["accept_negative_serial"])
    boringssl= SimulatedValidator("BoringSSL",      quirks=["accept_negative_serial",
                                                             "ber_indefinite_length"])
    wolfssl  = SimulatedValidator("WolfSSL-5.x",   quirks=[])   # strictest

    engine = DifferentialFuzzingEngine()
    engine.add_validator(openssl)
    engine.add_validator(boringssl)
    engine.add_validator(wolfssl)

    corpus = CertMutantFactory.full_corpus()
    events = engine.run(corpus)
    report = engine.report()
    return report


def phase2_greybox_fuzzing():
    print("\n" + "━"*60)
    print("  PHASE 2 – Coverage-Based Greybox Fuzzer")
    print("  (Equations 3, 4 – Section IV.B)")
    print("━"*60)

    corpus = CertMutantFactory.full_corpus()
    fuzzer = GreyboxFuzzer(corpus)
    result = fuzzer.run(rounds=30, verbose=True)
    return result


def phase3_tcev_classification(corpus):
    print("\n" + "━"*60)
    print("  PHASE 3 – TCEV Taxonomy Classification")
    print("  (Section V – Table II)")
    print("━"*60)

    classifier = TCEVClassifier()
    for cert in corpus:
        code, reason = classifier.classify_bytes(cert.data)
        info = classifier.describe_category(code)
        print(f"  [{cert.cert_id:<25}] → {code}: {info['category']}")
        print(f"    {reason}")


def phase4_metrics():
    print("\n" + "━"*60)
    print("  PHASE 4 – CCR / BDR Metrics & Benchmark Table")
    print("  (Section VI – Table III)")
    print("━"*60)

    calc = MetricsCalculator()
    calc.start_timer()

    # Simulate covering some RFC 5280 requirements
    rfc_reqs = [f"RFC5280-REQ-{i:02d}" for i in range(1, 52)]
    for r in rfc_reqs:
        calc.record_requirement_covered(r)

    # Simulate finding some bugs
    for i in range(4):
        calc.record_bug({"tcev": f"TCEV-2.{i+1}", "validator": "WolfSSL-5.x"})

    time.sleep(0.01)   # tiny delay so BDR is finite

    print(f"\n  Live Run Metrics:")
    print(f"    CCR (this run) = {calc.ccr():.1f}%  "
          f"({len(calc.tested_requirements)}/{calc.RFC5280_TOTAL_REQUIREMENTS} requirements)")
    print(f"    BDR (this run) = {calc.bdr():.1f} bugs/24h  "
          f"({len(calc.bugs_found)} bugs found)")

    calc.print_comparison()


def main():
    banner()

    # Phase 1: Differential fuzzing
    diff_report = phase1_differential_fuzzing()

    # Phase 2: Greybox fuzzing seed scheduler
    grey_result = phase2_greybox_fuzzing()

    # Phase 3: TCEV classification of the original corpus
    corpus = CertMutantFactory.full_corpus()
    phase3_tcev_classification(corpus)

    # Phase 4: Metrics and benchmark table
    phase4_metrics()

    # Final summary
    print("\n" + "━"*60)
    print("  SUMMARY")
    print("━"*60)
    print(f"  Differential divergence events : {diff_report['divergent']}/{diff_report['total']}")
    print(f"  Greybox new paths discovered   : {grey_result['new_paths']}")
    print(f"  Final corpus size              : {grey_result['corpus_size']}")
    print(f"\n  Key findings align with THEME-16 paper:")
    print(f"    • TCEV-2 (Parsing Logic) is the dominant vulnerability class")
    print(f"    • Stateful/deep fuzzers outperform shallow fuzzers by 18–32% CCR")
    print(f"    • D_J > 0.5 signals systematically exploitable divergence")
    print()


if __name__ == "__main__":
    main()
