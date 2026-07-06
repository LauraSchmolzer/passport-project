from PKD.parsers.ml_parser import parse_ml

from PKD.parsers.ldif_parser import ParseLDIF, RecordKind
from PKD.parsers.cert_parser import parse_cert
from PKD.parsers.crl_parser import parse_crl

from PKD.graph.link_builder import LinkGraphBuilder
from PKD.graph.crl_builder import CRLGraphBuilder
from PKD.graph.ds_builder import DSGraphBuilder

from PKD.repositories.cert_repo import CertificateRepository
from PKD.repositories.ml_repo import MasterListRepository
from PKD.repositories.country_repo import CountryRepository
from PKD.repositories.ds_repo import DSCertificateRepository
from PKD.repositories.crl_repo import CRLRepository

from PKD.db_models import MasterList,SessionLocal

import logging
logger = logging.getLogger(__name__)

from asn1crypto import x509 as asn1_x509
import os
from pathlib import Path
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

URL_ML = os.getenv("ICAOPKD_ML_PATH")
URL_DS_CRL = os.getenv("ICAOPKD_CRL_DS_PATH")

class PKDImporter:
    def __init__(self, session):
        self.session = session

        self.country_repo = CountryRepository(session)
        self.ml_repo = MasterListRepository(session)
        self.cert_repo = CertificateRepository(session)
        self.ds_repo = DSCertificateRepository(session)
        self.crl_repo = CRLRepository(session)

    def parse(self, ldif_ml_file: Path, ldif_ds_crl_file: Path):
        logger.info("Starting PKD import")

        with ldif_ml_file.open("rb") as f:
            parser = ParseLDIF(f)

            for ml_data in parser.process_file():
                logger.info("Processing ML for %s", ml_data.country)
                country = self.country_repo.get_or_create(ml_data.country)
                ml = self.ml_repo.get_or_create(ml_data, country)

                for cert in parse_ml(ml_data):
                    parsed = parse_cert(cert)

                    logger.debug(
                        "Parsed certificate",
                        extra={
                            "subject": parsed.subject_country,
                            "is_link": parsed.is_link_cert,
                        },
                    )

                    cert_country = self.country_repo.get_or_create(
                        parsed.subject_country,
                        parsed.subject_org,
                    )

                    self.cert_repo.create(parsed, cert_country, ml)

        logger.info("Starting CSCA link graph construction")
        LinkGraphBuilder(self.session).build()
        logger.info("Link graph construction complete")
        
        with ldif_ds_crl_file.open("rb") as f:
            parser = ParseLDIF(f)

            for data in parser.process_file():
                # Parse and add DS
                if data.kind == RecordKind.DS:
                    cert = asn1_x509.Certificate.load(data.raw)
                    parsed_ds = parse_cert(cert)
                    country = self.country_repo.get_or_create(parsed_ds.issuer_country)
                    self.ds_repo.create(parsed_ds, country)

                # Parse and add CRL
                elif data.kind == RecordKind.CRL:
                    parsed_crl = parse_crl(data.raw)
                    country = self.country_repo.get_or_create(parsed_crl.issuer_country)
                    self.crl_repo.create(parsed_crl, country)
                    continue

            # Link DS to CSCA 
            logger.info("Starting DS to CSCA graph construction")
            DSGraphBuilder(self.session).build()
            # Link CRL to CSCAs
            logger.info("Starting CRL to CSCA + DS revocation graph construction")
            CRLGraphBuilder(self.session).build()
        



if __name__ == "__main__":

    with SessionLocal() as session:
        importer = PKDImporter(session)
        
        importer.parse(Path(URL_ML),Path(URL_DS_CRL))
        session.commit()

        matrix = defaultdict(set)

        for ml in session.query(MasterList).all():
            ml_country = ml.country.code

        session.close()

                        
