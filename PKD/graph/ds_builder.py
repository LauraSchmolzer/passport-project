"""
    Link DS certs to issuing CSCA and validate signature.
"""

from PKD.verify.verify_cert import verify_signature, is_within_validity
from PKD.verify.crypto_helpers import get_publickey
from PKD.db_models import CSCACertificate, DSCertificate

import logging
logger = logging.getLogger(__name__)



class DSGraphBuilder:
    def __init__(self, session):
        self.session = session

    def build(self):
        ds_certs  = self.session.query(DSCertificate).all()
        csca_certs = self.session.query(CSCACertificate).filter_by(is_link_cert=False).all()

        ski_index = self._build_ski_index(csca_certs)

        for ds_cert in ds_certs:
            self._process_ds(ds_cert, ski_index)

    def _build_ski_index(self, certs):
        index = {}
        for cert in certs:
            if cert.ski:
                index[cert.ski] = cert
        return index

    def _process_ds(self, ds_cert: DSCertificate, ski_index: dict):
        if not ds_cert.aki:
            logger.warning(
                "DS cert has no AKI, cannot link to CSCA",
                extra={"ds_id": ds_cert.id, "subject_dn": ds_cert.subject_dn},
            )
            return

        issuing_csca = ski_index.get(ds_cert.aki)

        if issuing_csca is None:
            logger.warning(
                "No matching CSCA found for DS cert",
                extra={"ds_id": ds_cert.id, "subject_dn": ds_cert.subject_dn},
            )
            return

        # check validity of the DS certificate
        ds_cert.csca_id = issuing_csca.id
        try:
            if  is_within_validity(ds_cert.not_before, ds_cert.not_after):   
                issuer_pubkey = get_publickey(issuing_csca)
                ds_cert.signature_valid = verify_signature(ds_cert.raw_cert, issuer_pubkey)
            else:
                logger.warning("DSC signature valid but certificate outside validity window",extra={"ds_id": ds_cert.id})
                ds_cert.signature_valid = False   # or a separate `date_valid` flag — see below
        except Exception:
            logger.exception(
                "Error verifying DS cert signature",
                extra={"ds_id": ds_cert.id, "issuer_id": issuing_csca.id},
            )
            ds_cert.signature_valid = False

        if not ds_cert.signature_valid:
            logger.warning(
                "DS cert signature invalid",
                extra={"ds_id": ds_cert.id, "issuer_id": issuing_csca.id},
            )
