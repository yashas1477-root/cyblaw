"""
cert_generator.py
=================
Malformed X.509 Certificate Generator
Based on: TCEV Taxonomy (Section V) – THEME-16

Generates edge-case certificates covering TCEV-2 (Parsing Logic Exploitation)
sub-categories that are the most common divergence sources in the literature.

TCEV-2 Sub-categories implemented:
  2.1  BER indefinite-length encoding instead of DER
  2.2  Null-byte injection in Common Name (CN)
  2.3  Negative serial number (missing 0x00 padding)
  2.4  Zero-length Subject field
  2.5  Unrecognised critical extension
  2.6  Overlapping validity window (notBefore > notAfter)
"""

import struct
import os
from dataclasses import dataclass
from typing import List, Optional
from differential_fuzzer import CertificateInput


# ── Minimal ASN.1 / DER primitives ────────────────────────────────────────────
def der_tlv(tag: int, value: bytes) -> bytes:
    """Encode a DER TLV triplet."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + value


def der_sequence(contents: bytes) -> bytes:
    return der_tlv(0x30, contents)


def der_integer(value: int) -> bytes:
    """Encode a non-negative integer as DER INTEGER (with 0x00 pad if needed)."""
    if value == 0:
        return der_tlv(0x02, b"\x00")
    bs = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if bs[0] & 0x80:           # high bit set → prepend 0x00 to keep positive
        bs = b"\x00" + bs
    return der_tlv(0x02, bs)


def der_utf8string(text: str) -> bytes:
    return der_tlv(0x0C, text.encode())


def der_printablestring(text: str) -> bytes:
    return der_tlv(0x13, text.encode())


def der_utctime(s: str) -> bytes:
    """s e.g. '230101000000Z'"""
    return der_tlv(0x17, s.encode())


def der_oid(dotted: str) -> bytes:
    """Encode a dotted OID string to DER."""
    parts = list(map(int, dotted.split(".")))
    encoded = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        if part == 0:
            encoded += b"\x00"
        else:
            septets = []
            while part:
                septets.append(part & 0x7F)
                part >>= 7
            septets.reverse()
            for i, s in enumerate(septets):
                encoded += bytes([s | (0x80 if i < len(septets) - 1 else 0x00)])
    return der_tlv(0x06, encoded)


# OIDs used in certificates
OID_CN              = "2.5.4.3"
OID_O               = "2.5.4.10"
OID_C               = "2.5.4.6"
OID_RSA             = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_UNKNOWN_CRITICAL  = "1.3.6.1.4.1.99999.1"   # invented OID for TCEV-2.5


# ── Minimal RSA public key placeholder (512-bit for test only) ─────────────────
DUMMY_RSA_PUBKEY = bytes([
    0x30, 0x5c,  # SEQUENCE
    0x02, 0x55,  # INTEGER (modulus – 85 bytes, just zeros for structure test)
] + [0x00] * 85 + [
    0x02, 0x03, 0x01, 0x00, 0x01  # INTEGER exponent = 65537
])

DUMMY_SIGNATURE = b"\x00" * 64   # placeholder – not cryptographically valid


# ── Certificate builder ────────────────────────────────────────────────────────
def build_subject(cn: str, org: str = "TestOrg", country: str = "IN") -> bytes:
    return der_sequence(
        der_sequence(der_set(der_sequence(der_oid(OID_C) + der_printablestring(country)))) +
        der_sequence(der_set(der_sequence(der_oid(OID_O) + der_utf8string(org)))) +
        der_sequence(der_set(der_sequence(der_oid(OID_CN) + der_utf8string(cn))))
    )


def der_set(contents: bytes) -> bytes:
    return der_tlv(0x31, contents)


def build_validity(not_before: str = "230101000000Z",
                   not_after:  str = "250101000000Z") -> bytes:
    return der_sequence(der_utctime(not_before) + der_utctime(not_after))


def build_spki() -> bytes:
    """SubjectPublicKeyInfo (dummy RSA key, structure-only)."""
    algo = der_sequence(der_oid(OID_RSA) + der_tlv(0x05, b""))  # NULL params
    return der_sequence(algo + der_tlv(0x03, b"\x00" + DUMMY_RSA_PUBKEY))


def build_tbs(serial: bytes, subject_cn: str, validity: bytes,
              extensions: Optional[bytes] = None) -> bytes:
    """Build the TBSCertificate structure."""
    version      = der_tlv(0xA0, der_tlv(0x02, b"\x02"))          # v3
    serial_field = der_tlv(0x02, serial)
    sig_algo     = der_sequence(der_oid(OID_SHA256_WITH_RSA) + der_tlv(0x05, b""))
    issuer       = build_subject("TestCA")
    subj         = build_subject(subject_cn)
    spki         = build_spki()

    body = version + serial_field + sig_algo + issuer + validity + subj + spki
    if extensions:
        body += der_tlv(0xA3, extensions)
    return der_sequence(body)


def wrap_certificate(tbs: bytes) -> bytes:
    """Wrap TBS into a full Certificate structure with placeholder signature."""
    sig_algo  = der_sequence(der_oid(OID_SHA256_WITH_RSA) + der_tlv(0x05, b""))
    signature = der_tlv(0x03, b"\x00" + DUMMY_SIGNATURE)
    return der_sequence(tbs + sig_algo + signature)


# ── TCEV-2 Mutant generators ───────────────────────────────────────────────────
class CertMutantFactory:

    @staticmethod
    def valid_baseline() -> CertificateInput:
        """A well-formed, RFC-5280-compliant baseline certificate."""
        tbs  = build_tbs(b"\x01", "valid.example.com", build_validity())
        cert = wrap_certificate(tbs)
        return CertificateInput("BASELINE-001", cert, "DER",
                                "Well-formed baseline certificate", "")

    @staticmethod
    def tcev_2_1_ber_indefinite() -> CertificateInput:
        """
        TCEV-2.1 – BER indefinite-length encoding.
        DER mandates definite-length; some parsers silently accept BER.
        Replace the outer SEQUENCE length with 0x80 (indefinite) + EOC marker.
        """
        tbs  = build_tbs(b"\x02", "ber.example.com", build_validity())
        cert = wrap_certificate(tbs)
        # Patch: replace first definite-length byte with 0x80 (indefinite)
        cert_list = bytearray(cert)
        cert_list[1] = 0x80          # BER indefinite length
        cert_list += b"\x00\x00"     # End-Of-Contents (EOC)
        return CertificateInput("TCEV-2.1-BER", bytes(cert_list), "BER",
                                "BER indefinite-length encoding (RFC 5280 violation)",
                                "TCEV-2.1")

    @staticmethod
    def tcev_2_2_null_byte_cn() -> CertificateInput:
        """
        TCEV-2.2 – Null-byte injection in Common Name.
        Classic Moxie Marlinspike attack: CN = 'evil.com\x00.good.com'
        Some validators truncate at \x00, causing identity confusion.
        """
        # Manually craft CN with embedded null byte
        cn_raw = b"evil.example.com\x00.trusted.com"
        cn_field = der_tlv(0x0C, cn_raw)  # UTF8String with null
        cn_rdn   = der_sequence(der_set(der_sequence(der_oid(OID_CN) + cn_field)))
        custom_subj = der_sequence(cn_rdn)

        version  = der_tlv(0xA0, der_tlv(0x02, b"\x02"))
        serial   = der_tlv(0x02, b"\x03")
        sig_algo = der_sequence(der_oid(OID_SHA256_WITH_RSA) + der_tlv(0x05, b""))
        issuer   = build_subject("TestCA")
        validity = build_validity()
        spki     = build_spki()

        tbs  = der_sequence(version + serial + sig_algo + issuer + validity + custom_subj + spki)
        cert = wrap_certificate(tbs)
        return CertificateInput("TCEV-2.2-NULL-CN", cert, "DER",
                                "Null-byte injected in Common Name field",
                                "TCEV-2.2")

    @staticmethod
    def tcev_2_3_negative_serial() -> CertificateInput:
        """
        TCEV-2.3 – Negative serial number.
        RFC 5280 §4.1.2.2: serial MUST be positive. Encode as INTEGER with
        high bit set and no leading 0x00 pad → negative in DER.
        """
        negative_serial = b"\xFF\x01"   # 0xFF = high bit set → negative integer
        tbs  = build_tbs(negative_serial, "neg-serial.example.com", build_validity())
        cert = wrap_certificate(tbs)
        return CertificateInput("TCEV-2.3-NEG-SERIAL", cert, "DER",
                                "Negative serial number (missing 0x00 pad)",
                                "TCEV-2.3")

    @staticmethod
    def tcev_2_4_zero_length_subject() -> CertificateInput:
        """
        TCEV-2.4 – Zero-length Subject field.
        Empty SEQUENCE for Subject. Some validators crash, others reject silently.
        """
        empty_subject = der_sequence(b"")   # SEQUENCE {}

        version  = der_tlv(0xA0, der_tlv(0x02, b"\x02"))
        serial   = der_tlv(0x02, b"\x04")
        sig_algo = der_sequence(der_oid(OID_SHA256_WITH_RSA) + der_tlv(0x05, b""))
        issuer   = build_subject("TestCA")
        validity = build_validity()
        spki     = build_spki()

        tbs  = der_sequence(version + serial + sig_algo + issuer + validity + empty_subject + spki)
        cert = wrap_certificate(tbs)
        return CertificateInput("TCEV-2.4-ZERO-SUBJ", cert, "DER",
                                "Zero-length Subject SEQUENCE",
                                "TCEV-2.4")

    @staticmethod
    def tcev_2_5_unknown_critical_ext() -> CertificateInput:
        """
        TCEV-2.5 – Unrecognised critical extension.
        RFC 5280 §4.2: if an extension is critical and unrecognised, MUST reject.
        Many parsers silently accept.
        """
        ext_oid     = der_oid(OID_UNKNOWN_CRITICAL)
        critical    = der_tlv(0x01, b"\xFF")           # BOOLEAN TRUE
        ext_value   = der_tlv(0x04, b"\xDE\xAD\xBE\xEF")  # OCTET STRING
        extension   = der_sequence(ext_oid + critical + ext_value)
        extensions  = der_sequence(extension)

        tbs  = build_tbs(b"\x05", "crit-ext.example.com", build_validity(), extensions)
        cert = wrap_certificate(tbs)
        return CertificateInput("TCEV-2.5-CRIT-EXT", cert, "DER",
                                "Unrecognised critical extension (must reject per RFC 5280)",
                                "TCEV-2.5")

    @staticmethod
    def tcev_2_6_inverted_validity() -> CertificateInput:
        """
        TCEV-2.6 – notBefore > notAfter (inverted validity window).
        RFC 5280 §4.1.2.5: notAfter MUST be >= notBefore.
        """
        inverted_validity = build_validity("250101000000Z", "230101000000Z")
        tbs  = build_tbs(b"\x06", "inverted.example.com", inverted_validity)
        cert = wrap_certificate(tbs)
        return CertificateInput("TCEV-2.6-INV-VALIDITY", cert, "DER",
                                "Inverted validity window (notBefore > notAfter)",
                                "TCEV-2.6")

    @classmethod
    def full_corpus(cls) -> List[CertificateInput]:
        """Return all TCEV-2 test certificates plus a clean baseline."""
        return [
            cls.valid_baseline(),
            cls.tcev_2_1_ber_indefinite(),
            cls.tcev_2_2_null_byte_cn(),
            cls.tcev_2_3_negative_serial(),
            cls.tcev_2_4_zero_length_subject(),
            cls.tcev_2_5_unknown_critical_ext(),
            cls.tcev_2_6_inverted_validity(),
        ]
