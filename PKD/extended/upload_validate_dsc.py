"""
     This file shows how a DSC can be validated and stored. 

        - AS THIS FILE USES THE ICAO PKD IT IS IMPORTANT TO NOT USE FOR COMMERCIAL PURPOSES !!!
"""

from PKD.parsers.cert_parser import parse_cert
from PKD.repositories.ds_repo import DSCertificateRepository
from PKD.repositories.country_repo import CountryRepository
from PKD.parsers.ldif_parser import ParseLDIF, RecordKind

from PKD.graph.ds_builder import DSGraphBuilder
from PKD.graph.crl_builder import CRLGraphBuilder

from asn1crypto import x509 as asn1_x509

from PKD.db_models import SessionLocal, CSCACertificate

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ICAO_LDIF_PATH = Path(os.getenv("ICAO_LDIF_PATH", "data/icaopkd-001-complete-10203.ldif"))

def get_candidate_cscas(session, country_id: int, aki: bytes | None) -> list[CSCACertificate]:
    candidates = (
        session.query(CSCACertificate)
        .filter(CSCACertificate.country_id == country_id)
        .filter(CSCACertificate.aki == aki)
        .all()
    )
    return candidates

def upload_validate_dsc():
    with SessionLocal() as session:
        print("=-=-=-=-=-=-=-=-=-=-=-= Upload DSCs =-=-=-=-=-=-=-=-=-=-=-=")
        ds_repo = DSCertificateRepository(session)
        country_repo = CountryRepository(session)

        with ICAO_LDIF_PATH.open("rb") as f:
            print("===== Start loading DS Certificates =====")
            parser = ParseLDIF(f)

            for data in parser.process_file():
                # Parse and add DS
                if data.kind != RecordKind.DS:
                    continue
                
                cert = asn1_x509.Certificate.load(data.raw)
                parsed_ds = parse_cert(cert)

                # It seems that one DSC in the ldif file is unknown
                if parsed_ds.subject_country == None:
                    continue
                
                cert_country = country_repo.get_or_create(parsed_ds.subject_country, parsed_ds.subject_org)
                ds_repo.create(parsed_ds, cert_country)

            session.commit()
            # Link DS to CSCA
            print('=-=-=-=-=-=-= Link DSCs to CSCAs =-=-=-=-=-=-=')
            DSGraphBuilder(session).build()
            session.commit()

            # Link CRL to DSCs
            print('=-=-=-=-=-=-= Link CRLs to DSCs =-=-=-=-=-=-=')
            CRLGraphBuilder(session).build_revocations()

            session.commit()
            print("=-=-=-=-=-=-=-=-=-=-=-= SUCCESS =-=-=-=-=-=-=-=-=-=-=-=")
    
upload_validate_dsc()