"""
    Link CRL to certificate and validate signature.
"""

from PKD.verify.verify_cert import verify_crl_signature, is_within_validity
from PKD.verify.crypto_helpers import get_publickey
from PKD.db_models import CSCACertificate, CRL, DSCertificate

from datetime import datetime
import logging
logger = logging.getLogger(__name__)


class CRLGraphBuilder:
    def __init__(self, session):
        self.session = session

    def build(self):
        crls = self.session.query(CRL).all()
        csca_certs = self.session.query(CSCACertificate).filter_by(is_link_cert=False).all()

        ski_index = self._build_ski_index(csca_certs)

        for crl in crls:
            self._process_crl(crl, ski_index)

    def _build_ski_index(self, certs):
        index = {}
        for cert in certs:
            if cert.ski:
                index[cert.ski] = cert
        return index

    def _process_crl(self, crl: CRL, ski_index: dict):
        if not crl.aki:
            logger.warning(
                "CRL has no AKI, cannot link to CSCA",
                extra={"crl_id": crl.id, "issuer_dn": crl.issuer_dn},
            )
            return

        issuing_csca = ski_index.get(crl.aki)

        if issuing_csca is None:
            logger.warning(
                "No matching CSCA found for CRL",
                extra={"crl_id": crl.id, "issuer_dn": crl.issuer_dn},
            )
            return

        # link it
        crl.csca_id = issuing_csca.id

        # verify signature
        
        try:
            if is_within_validity(issuing_csca.not_before, issuing_csca.not_after):

                issuer_pubkey = get_publickey(issuing_csca)
                crl.signature_valid = verify_crl_signature(crl.raw_crl, issuer_pubkey)
            else:
                logger.debug(
                    "Outdated signature", extra={
                        "country": issuing_csca.country.code,
                        "not_after": issuing_csca.not_after}
                )
                crl.signature_valid = False
        except Exception:
            logger.exception(
                "Error verifying CRL signature",
                extra={"crl_id": crl.id, "issuer_id": issuing_csca.id},
            )
            crl.signature_valid = False

        if not crl.signature_valid:
            logger.warning(
                "CRL signature invalid",
                extra={"crl_id": crl.id, "issuer_id": issuing_csca.id},
            )
        
        # Only when crl valid
        self._apply_revocations(crl)

    def _apply_revocations(self, crl: CRL):
        if not crl.revoked_serials:
            return

        ds_certs = (
            self.session.query(DSCertificate)
            .filter_by(csca_id=crl.csca_id)
            .all()
        )

        matched = 0
        for ds in ds_certs:
            revoked_at = crl.revoked_serials.get(ds.serial_number)
            if revoked_at:
                ds.is_revoked      = True
                ds.revoked_at      = datetime.fromisoformat(revoked_at)
                ds.revoking_crl_id = crl.id
                matched += 1

        logger.info(
            "Revocation linking complete",
            extra={
                "crl_id":         crl.id,
                "revoked_in_crl": len(crl.revoked_serials),
                "matched_in_db":  matched,
            }
        )