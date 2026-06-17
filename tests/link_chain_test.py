"""
    This file shows the existing chain of certificates for a country of choice.
    Tests and verifies the link certifactes from the DB.
"""

import pytest
from collections import defaultdict
from PKD.db_models import MasterList, CSCACertificate, SessionLocal

COUNTRY = "NL"

def test_cert_linkcerts():
    with SessionLocal() as session:
        certs = (
            session.query(CSCACertificate)
            .join(CSCACertificate.country)
            .filter(
                CSCACertificate.country.has(code=COUNTRY),
            )
            .order_by(CSCACertificate.not_before.asc())  # Has to be chronological order
            .all()
        )
        
        
test_cert_linkcerts()