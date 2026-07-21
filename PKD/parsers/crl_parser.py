from PKD.load.sha_helpers import sha256
from dataclasses import dataclass
from datetime import datetime
from asn1crypto import crl as asn1_crl
from PKD.verify.crypto_helpers import get_aki_ski
from PKD.db_models import CSCACertificate

import logging
logger = logging.getLogger(__name__)


@dataclass
class RevokedSerial:
    serial_number: str
    revocation_date: datetime


@dataclass
class ParsedCRL:
    raw: bytes
    sha256_finger: str

    issuer_dn: str
    issuer_country: str | None
    issuer_org: str | None
    issuer_cn: str | None

    this_update: datetime
    next_update: datetime | None

    aki: bytes | None

    revoked: list[RevokedSerial]
    csca: CSCACertificate


def _get_revoked(crl: asn1_crl.CertificateList) -> list[RevokedSerial]:
    revoked = crl['tbs_cert_list']['revoked_certificates']
    if revoked.native is None:
        return []
    return [
        RevokedSerial(
            serial_number=str(rc['user_certificate'].native),
            revocation_date=rc['revocation_date'].native,
        )
        for rc in revoked
    ]


def parse_crl(result: tuple[bytes, CSCACertificate]) -> ParsedCRL:
    raw, csca = result

    crl = asn1_crl.CertificateList.load(raw)
    issuer = crl['tbs_cert_list']['issuer'].native
    next_update = crl['tbs_cert_list']['next_update']

    if crl['tbs_cert_list']['crl_extensions'].native is not None:
        aki, _ = get_aki_ski(crl, extension_field="crl_extensions", cert_field='tbs_cert_list')
    else:
        aki = None

    return ParsedCRL(
        raw             = raw,
        sha256_finger   = sha256(raw),

        issuer_dn       = crl['tbs_cert_list']['issuer'].human_friendly,
        issuer_country  = issuer.get("country_name", "").strip().upper() or None,
        issuer_org      = issuer.get("organization_name"),
        issuer_cn       = issuer.get("common_name"),

        this_update     = crl['tbs_cert_list']['this_update'].native,
        next_update     = next_update.native if next_update else None,

        aki = aki,
        revoked = _get_revoked(crl),
        csca = csca,
    )