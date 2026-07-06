from PKD.db_models import DSCertificate

class DSCertificateRepository:
    def __init__(self, session):
        self.session = session

    def get_by_fingerprint(self, fp: str):
        return (
            self.session.query(DSCertificate)
            .filter_by(sha256_finger=fp)
            .one_or_none()
        )

    def create(self, cert_data, country):

        cert = DSCertificate(
            subject_dn=cert_data.subject_dn,
            issuer_dn = cert_data.issuer_dn,

            raw_cert=cert_data.raw,
            not_before=cert_data.not_before,
            not_after=cert_data.not_after,
            serial_number=cert_data.serial_number,
            sha256_finger=cert_data.sha256_finger,
            aki = cert_data.aki,
            ski = cert_data.ski,
            country=country,
        )

        self.session.add(cert)
        self.session.flush()
        return cert