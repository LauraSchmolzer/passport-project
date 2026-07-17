"""
    Link CRL to certificate to DSC

    BUILD_REVOCATIONS : Links CRL serials to DS certificates
"""

from PKD.db_models import CRL, DSCertificate

from datetime import datetime
import logging
logger = logging.getLogger(__name__)


class CRLGraphBuilder:
    def __init__(self, session):
        self.session = session

    def build_revocations(self):
        crls = self.session.query(CRL).filter_by(signature_valid=True).all()

        for crl in crls:
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