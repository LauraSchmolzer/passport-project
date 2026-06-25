from PKD.load_mls.load_ml import sha256
from dataclasses import dataclass
from datetime import datetime
from asn1crypto import x509 as asn1_x509

def is_link_certificate(cert: asn1_x509.Certificate) -> bool:
    extensions = cert['tbs_certificate']['extensions']

    ski = None
    aki = None
    for ext in extensions:
        try:
            if ext['extn_id'].native == 'key_identifier':
                ski = ext['extn_value'].parsed.native
            elif ext['extn_id'].native == 'authority_key_identifier':
                aki_field = ext['extn_value'].parsed['key_identifier']
                aki = aki_field.native if aki_field else None
        except ValueError:
            # Malformed extension bytes on this cert; skip it and fall back below
            continue

    if ski is None or aki is None:
        return cert.subject.human_friendly != cert.issuer.human_friendly

    return ski != aki

@dataclass
class ParsedCert:
    raw: bytes

    sha256_finger: str
    serial_number: str

    subject_dn: str
    issuer_dn: str

    subject_country: str | None
    issuer_country: str | None

    subject_org: str | None
    issuer_org: str | None

    subject_cn: str | None
    issuer_cn: str | None

    not_before: datetime
    not_after: datetime

    is_link_cert: bool

def parse_cert(cert: asn1_x509.Certificate) -> ParsedCert:
    der = cert.dump()

    subject = cert.subject.native
    issuer = cert.issuer.native

    return ParsedCert(
        raw             = der,
        sha256_finger   = sha256(der),
        subject_dn      = cert.subject.human_friendly,
        issuer_dn       = cert.issuer.human_friendly,

        subject_country = subject.get("country_name", "").strip().upper() or None,
        subject_org     = subject.get("organization_name"),
        subject_cn      = subject.get("common_name"),

        issuer_country = issuer.get("country_name", "").strip().upper() or None,
        issuer_org     = issuer.get("organization_name"),
        issuer_cn      = issuer.get("common_name"),

        serial_number   = str(cert.serial_number),
        not_before      = cert['tbs_certificate']['validity']['not_before'].native,
        not_after       = cert['tbs_certificate']['validity']['not_after'].native,

        is_link_cert    = is_link_certificate(cert)
        )