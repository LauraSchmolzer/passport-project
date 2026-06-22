from PKD.parsers.ml_parser import parse_ml
from PKD.load_ml import load_mls, ParsedML
from PKD.parsers.cert_parser import parse_cert, ParsedCert
from collections import defaultdict

from PKD.crypto_helpers import _get_aki_ski, _verify_link

from sqlalchemy.orm import Session

from PKD.db_models import (
    MasterList,
    CSCACertificate,
    Country,
    SessionLocal,
    CSCALink
)

class PKDImporter:
    def __init__(self, session: Session):
        self.session = session

    def parse(self): 
        for ml_data in load_mls():
            # Create country for ml
            country_db = self.__create_country(ml_data.country)
            # Store Master List data
            ml_db = self.__create_ml(ml_data, country_db)
            # Parse the certificates of the ml_data
            for cert in parse_ml(ml_data):
                # Parse the certificate
                parsed_cert = parse_cert(cert)
                # Create country of cert if not existing yet (and add parsed name)
                country_cert_db = self.__create_country(
                    parsed_cert.subject_country,
                    parsed_cert.subject_org,
                )
                # Create certificate and add to ml
                self.__create_cert(parsed_cert,country_cert_db,ml_db)
            
        self.__link_certs()


    def __create_country(self, cc: str, organization: str | None = None) -> Country:
        # Does not make duplicates, now scoped by (code, organization)
        country = (
            self.session.query(Country)
            .filter_by(code=cc.upper(), organization=organization)
            .one_or_none()
        )

        if country is None:
            country = Country(
                code=cc.upper(),
                name=cc.upper(),
                organization=organization,
            )
            self.session.add(country)
            self.session.flush()

        return country
    
    def __create_ml(self, ml_data: ParsedML, country) -> MasterList:
        # Does not make duplicates
        ml = (
            self.session.query(MasterList)
            .filter_by(sha256_finger = ml_data.sha256_finger)
            .one_or_none()
        )

        if ml is None:
            ml = MasterList(
                sequence_number=1,
                raw_ml = ml_data.raw,
                sha256_finger = ml_data.sha256_finger,
                country = country
            )
            self.session.add(ml)
            self.session.flush()

        return ml
    
    def __create_cert(self, cert_data: ParsedCert, country_cert: Country, ml: MasterList) -> CSCACertificate:
        # Check if the certificate already exists globally to avoid duplicates
        cert = (
            self.session.query(CSCACertificate)
            .filter_by(sha256_finger=cert_data.sha256_finger)
            .one_or_none()
        )

        if cert is None:
            cert = CSCACertificate(
                subject_dn    = cert_data.subject_dn,
                issuer_dn     = cert_data.issuer_dn,
                raw_cert      = cert_data.raw,
                not_before    = cert_data.not_before,
                not_after     = cert_data.not_after,
                serial_number = cert_data.serial_number,
                sha256_finger = cert_data.sha256_finger,
                country       = country_cert,
                is_link_cert  = cert_data.is_link_cert,
            )
            self.session.add(cert)
            self.session.flush()

        # Associate with the Master List
        if ml not in cert.master_lists:
            cert.master_lists.append(ml)

        return cert
    
    def __link_certs(self):
        link_certificates = self.session.query(CSCACertificate).filter_by(is_link_cert=True).all()
        all_csca_certs = self.session.query(CSCACertificate).filter_by(is_link_cert=False).all()

        ski_to_cert: dict[bytes, CSCACertificate] = {}
        for csca in all_csca_certs:
            aki, ski = _get_aki_ski(csca)
            if ski is not None:
                ski_to_cert[ski] = csca


        for link_cert in link_certificates:
            aki, ski = _get_aki_ski(link_cert)

            old_csca_cert = ski_to_cert.get(aki) if aki else None
            new_csca_cert = ski_to_cert.get(ski) if ski else None

            # cryptographically verify signature before trusting the Link
            if old_csca_cert == None:
                print(f"No issuer found for the link certificate {link_cert.country.code,link_cert.not_after}")

                # NOTE: To inspect why certain certs might not link 
                #other_links = self.session.query(CSCACertificate).filter_by(is_link_cert=True, country_id = link_cert.country_id ).all()
                #for l in other_links:
                #    print(l.country.code, l.not_after)
                continue

            if not _verify_link(link_cert,old_csca_cert):
                print(f"This link cert is not right{link_cert.country.code}")
            
            link_cert.source_certs = old_csca_cert

            if new_csca_cert is None:
                print(
                    f"No target CSCA found for link cert "
                    f"{link_cert.country.code, link_cert.not_after}"
                )
                continue
            new_csca_cert.source_certs = link_cert
            edge = CSCALink(
            from_csca_id=old_csca_cert.id,
            to_csca_id=new_csca_cert.id,
            link_cert_id=link_cert.id
            )

            self.session.add(edge)


if __name__ == "__main__":

    with SessionLocal() as session:
        importer = PKDImporter(session)
        importer.parse()
        session.commit()
        from collections import defaultdict

        matrix = defaultdict(set)

        for ml in session.query(MasterList).all():
            ml_country = ml.country.code

            for cert in ml.csca_certs:

                if cert.country.code == "DK":
                    matrix[ml_country].add((cert.not_after, cert.sha256_finger))

        session.close()

                        
