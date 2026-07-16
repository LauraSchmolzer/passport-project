"""
    Get distribution points and and fetch CRLs for certificates
"""

from typing import Optional, Sequence

from CRL.load.get_URL import get_crl_urls
from CRL.load.fetch_crl import fetch_crl

from PKD.db_models import CSCACertificate
from PKD.verify.crypto_helpers import _get_publickey
from PKD.verify.verify_cert import _verify_crl_signature

import logging
logger = logging.getLogger(__name__)

_ICAO_PREFIXES = (
    "https://pkddownload1.icao.int/CRLs/",
    "https://pkddownload2.icao.int/CRLs/",
)

def filter_icao_urls(urls: list[str]) -> list[str]:
    return [u for u in urls if not u.startswith(_ICAO_PREFIXES)]

class GetCRL:
    def __init__(self, session):
        self.session = session

    def get_crl(self, cert, icao = True) -> Optional[tuple]:
        urls = get_crl_urls(cert) or []

        if not urls:
            logger.info("No CRL distribution points found", extra={"issuer": cert.issuer_dn})
            return None
        
        if not icao:
            urls = filter_icao_urls(urls)

        url, raw = fetch_crl(urls)
        if raw is None:
            logger.warning("Could not fetch CRL from any distribution point", extra={"urls": urls})
            return None

        candidates = self._get_candidate_cscas(cert)
        if not candidates:
            logger.warning("No CSCA candidates on file to verify CRL signature", extra={"issuer": cert.issuer_dn})
            return None

        # Try multiple CSCAs corresponding to the country to see if it signed the CRL
        for csca in candidates:

            pubkey = _get_publickey(csca)

            if _verify_crl_signature(raw, pubkey):
                logger.info(
                    "CRL signature verified" ,
                    extra={"url": url, "csca_id": csca.id, "csca_not_before": csca.not_before},
                )
                return (raw, csca)

            logger.debug("CRL signature failed against candidate", extra={"csca_id": csca.id})

        logger.warning(
            "CRL fetched but signature did not verify against any known CSCA for this issuer",
            extra={"url": url, "issuer": cert.issuer_dn},
        )
        return None

    def _get_candidate_cscas(self, cert) -> Sequence[CSCACertificate]:

        candidates = (
            self.session.query(CSCACertificate)
            .filter(
                CSCACertificate.country_id == cert.country_id,
                CSCACertificate.is_link_cert.is_(False),
            )
            .all()
        )
        candidates.sort(key=lambda c: (c.ski == cert.aki, c.not_before), reverse=True)
        return candidates
