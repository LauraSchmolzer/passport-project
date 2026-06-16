from PKD.parsers.ml_parser import parse_ml
from PKD.load_ml import load_mls, ParsedML
from PKD.parsers.cert_parser import parse_cert, ParsedCert

from sqlalchemy.orm import sessionmaker, Session

from PKD.db_models import (
    MasterList,
    CSCACertificate,
    Country,
    engine
)


class PKDImporter:
    def __init__(self, session: Session):
        self.session = session

    def parse(self): 
        for ml_data in load_mls():
            country_db = self.__create_country(ml_data.country)

            ml_db = self.__create_ml(ml_data, country_db)
        
            for cert in parse_ml(ml_data):
                parsed_cert = parse_cert(cert)
                # Create country of cert if not existing yet (and add parsed name)
                country_cert_db = self.__create_country(parsed_cert.subject_country)
                # create certificate
                cert_db = self.__create_cert(parsed_cert,country_cert_db,ml_db)
                print(cert_db)

            break


    def __create_country(self, cc: str) -> Country:
        # Does not make duplicates
        country = (
            self.session.query(Country)
            .filter_by(code=cc)
            .one_or_none()
        )

        if country is None:
            country = Country(
                code=cc,
                name=cc
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
    
    def __create_cert(self, cert_data: ParsedCert, country_cert: Country ,ml: MasterList) -> CSCACertificate:
        # Does not make duplicates
        cert = (
            self.session.query(CSCACertificate)
            .filter_by(sha256_finger = cert_data.sha256_finger)
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
            )
            self.session.add(cert)
            self.session.flush()

        if ml not in cert.master_lists:
            cert.master_lists.append(ml)

        return cert



if __name__ == "__main__":
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        importer = PKDImporter(session)
        importer.parse()
        session.commit()
 
                    
