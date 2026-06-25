from PKD.parsers.ml_parser import parse_ml
from PKD.load_mls.load_ml import load_mls
from PKD.parsers.cert_parser import parse_cert
from collections import defaultdict
from PKD.graph.link_builder import LinkGraphBuilder
from PKD.repositories.cert_repo import CertificateRepository
from PKD.repositories.ml_repo import MasterListRepository
from PKD.repositories.country_repo import CountryRepository

from sqlalchemy.orm import Session
import logging

from PKD.db_models import (
    MasterList,
    SessionLocal,
)

class PKDImporter:
    def __init__(self, session):
        self.session = session

        self.country_repo = CountryRepository(session)
        self.ml_repo = MasterListRepository(session)
        self.cert_repo = CertificateRepository(session)

    def parse(self):
        for ml_data in load_mls():

            country = self.country_repo.get_or_create(ml_data.country)
            ml = self.ml_repo.get_or_create(ml_data, country)

            for cert in parse_ml(ml_data):
                parsed = parse_cert(cert)

                cert_country = self.country_repo.get_or_create(
                    parsed.subject_country,
                    parsed.subject_org,
                )

                self.cert_repo.create(parsed, cert_country, ml)

        LinkGraphBuilder(self.session).build()
    


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

                        
