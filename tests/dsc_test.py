
from PKD.db_models import SessionLocal, DSCertificate


def test_dsc():
    with SessionLocal() as session:
        # Small test
        is_revoked = 0
        DSCs = session.query(DSCertificate).all()
        for ds in DSCs:
            if ds.revoking_crl_id != None:
                print(f"DS Certificate found for {ds.country.code} with CSCA {ds.csca_id} and CRL {ds.revoking_crl_id}")
                is_revoked +=1
        
        print(f"There are {is_revoked} DSCs revoked")

test_dsc()