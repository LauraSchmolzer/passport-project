from PKD.load_ml import sha256
from dataclasses import dataclass
from datetime import datetime
from asn1crypto import x509 as asn1_x509

@dataclass
class ParsedCert:
    raw: bytes
    sha256: str
    subject_dn: dict
    issuer_dn: dict
    serial_number: str
    not_before: datetime
    not_after: datetime

def parse_cert(cert: asn1_x509.Certificate) -> ParsedCert:
    der = cert.dump()

    return ParsedCert(
        raw             = der,
        sha256          = sha256(der),
        subject_dn      = cert.subject.native,
        issuer_dn       = cert.issuer.native,
        serial_number   = str(cert.serial_number),
        not_before      = cert['tbs_certificate']['validity']['not_before'].native,
        not_after       = cert['tbs_certificate']['validity']['not_after'].native,
    )