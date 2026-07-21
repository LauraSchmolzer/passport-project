from PKD.parsers.ml_parser import parse_ml
from PKD.load.load_ml import load_mls
from PKD.parsers.cert_parser import parse_cert

from PKD.graph.link_builder import LinkGraphBuilder
from PKD.graph.score_builder import ScoreCSCABuilder

from PKD.repositories.cert_repo import CertificateRepository
from PKD.repositories.ml_repo import MasterListRepository
from PKD.repositories.country_repo import CountryRepository

from PKD.db_models import SessionLocal

import logging
logger = logging.getLogger(__name__)


class PKDImporter:
    def __init__(self, session):
        self.session = session

        self.country_repo = CountryRepository(session)
        self.ml_repo = MasterListRepository(session)
        self.cert_repo = CertificateRepository(session)

    def parse(self):
        logger.info("Starting PKD import")

        for ml_data in load_mls():
            logger.info("Processing ML for %s", ml_data.country)

            country = self.country_repo.get_or_create(ml_data.country)
            ml = self.ml_repo.get_or_create(ml_data, country)

            for cert in parse_ml(ml_data):
                parsed = parse_cert(cert)

                logger.debug("Parsed certificate", extra={
                    "subject": parsed.subject_country,
                    "is_link": parsed.is_link_cert}
                    )

                cert_country = self.country_repo.get_or_create(
                    parsed.subject_country,
                    parsed.subject_org,
                )

                self.cert_repo.create(parsed, cert_country, ml)

        self.session.commit()

        logger.info("Staring CSCA link graph construction")
        LinkGraphBuilder(self.session).build()
        logger.info("Link Graph construstion complete")
        
        self.session.commit()

        logger.info("Staring CSCA scoring")
        ScoreCSCABuilder(self.session).score()
        logger.info("CSCA scoring complete")
        
        self.session.commit()
    


if __name__ == "__main__":
    with SessionLocal() as session:
        importer = PKDImporter(session)
        importer.parse()
        session.close()

                        
