from PKD.db_models import CRL
from PKD.parsers.crl_parser import ParsedCRL

class CRLRepository:
    def __init__(self, session):
        self.session = session

    def get_by_fingerprint(self, fp: str) -> CRL | None:
        return (
            self.session.query(CRL)
            .filter_by(sha256_finger=fp)
            .one_or_none()
        )

    def create(self, parsed: ParsedCRL, country) -> CRL:

        existing = self.get_by_fingerprint(parsed.sha256_finger)

        if existing is not None:
            return existing
    
        crl = CRL(
            raw_crl       = parsed.raw,
            sha256_finger = parsed.sha256_finger,
            issuer_dn     = parsed.issuer_dn,
            this_update   = parsed.this_update,
            next_update   = parsed.next_update,
            aki           = parsed.aki,
            country       = country,
            revoked_serials = {
                entry.serial_number: entry.revocation_date.isoformat()
                for entry in parsed.revoked
            },
        )
        self.session.add(crl)
        self.session.flush()
        return crl

