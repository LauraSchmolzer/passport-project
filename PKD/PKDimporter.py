from PKD.parsers.ml_parser import parse_ml
from PKD.load_ml import load_mls, MLdata
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
        for ml in load_mls():
            country = self.__create_country(ml.country)
            # Add ML to DB
            for cert in parse_ml(ml):
                parsed_cert = parse_cert(cert)
                # Create country of cert if not existing yet (and add parsed name)
                country_cert = self.__create_country(parsed_cert.subject.get("country_name"))
                # add cert to DB
                # add cert to ML


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



if __name__ == "__main__":
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        importer = PKDImporter(session)
        importer.parse()
        session.commit()
 
                    
