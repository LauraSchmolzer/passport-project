from PKD.verify.crypto_helpers import _get_aki_ski, _verify_link
from PKD.db_models import CSCACertificate, CSCALink
from collections import defaultdict

import logging
logger = logging.getLogger(__name__)


class LinkGraphBuilder:
    def __init__(self, session):
        self.session = session

    def build(self):
        link_certs = (self.session.query(CSCACertificate).filter_by(is_link_cert=True).all())

        csca_certs = (self.session.query(CSCACertificate).filter_by(is_link_cert=False).all())

        ski_index = self._build_ski_index(csca_certs)

        for link_cert in link_certs:
            self._process_link(link_cert, ski_index)

    def _build_ski_index(self, certs):
        index = {}

        for cert in certs:
            ski = cert.ski
            if ski:
                index[ski] = cert

        return index

    def _process_link(self, link_cert, ski_index):
        aki = link_cert.aki
        ski = link_cert.ski

        old_csca = ski_index.get(aki) if aki else None
        new_csca = ski_index.get(ski) if ski else None

        if old_csca is None:
            logger.debug(
                "No issuer found", extra={
                    "country": link_cert.country.code,
                    "not_after": link_cert.not_after}
            )
            return

        if not _verify_link(link_cert, old_csca):
            logger.debug(
                "Invalid signature", extra={
                    "country": link_cert.country.code,
                    "not_after": link_cert.not_after}
            )
            return

        if new_csca is None:
            logger.debug(
                "No target CSCA", extra={
                    "country": link_cert.country.code,
                    "not_after": link_cert.not_after}
            )
            return

        # store relationship
        edge = CSCALink(
            from_csca_id=old_csca.id,
            to_csca_id=new_csca.id,
            link_cert_id=link_cert.id
        )

        self.session.add(edge)