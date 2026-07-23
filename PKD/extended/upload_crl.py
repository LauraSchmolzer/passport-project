"""
    Upload a crl, fetched from a CRL distribution point, into the database.
"""

from PKD.parsers.crl_parser import parse_crl
from PKD.repositories.crl_repo import CRLRepository
from PKD.CRL.get_crl import GetCRL

from PKD.db_models import SessionLocal, CSCACertificate

INCLUDE_ICAO = True

def extend_with_CRL():
    with SessionLocal() as session:
        csca_certs = session.query(CSCACertificate).all()

        getter = GetCRL(session)
        repo = CRLRepository(session)

        for csca in csca_certs:
            result = getter.get_crl(csca, INCLUDE_ICAO)
            if result is None:
                continue

            parsed_crl = parse_crl(result)
            repo.create(parsed_crl)

        session.commit()

extend_with_CRL()
