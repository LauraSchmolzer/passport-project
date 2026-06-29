from PKD.db_models import CSCACertificate

class CertificateRepository:
    def __init__(self, session):
        self.session = session

    def get_by_fingerprint(self, fp: str):
        return (
            self.session.query(CSCACertificate)
            .filter_by(sha256_finger=fp)
            .one_or_none()
        )

    def create(self, cert_data, country, ml):
        cert = self.get_by_fingerprint(cert_data.sha256_finger)

        if cert:
            if ml not in cert.master_lists:
                cert.master_lists.append(ml)
            return cert

        cert = CSCACertificate(
            subject_dn=cert_data.subject_dn,
            issuer_dn=cert_data.issuer_dn,
            raw_cert=cert_data.raw,
            not_before=cert_data.not_before,
            not_after=cert_data.not_after,
            serial_number=cert_data.serial_number,
            sha256_finger=cert_data.sha256_finger,
            aki = cert_data.aki,
            ski = cert_data.ski,
            country=country,
            is_link_cert=cert_data.is_link_cert,
        )

        self.session.add(cert)
        self.session.flush()

        cert.master_lists.append(ml)

        return cert