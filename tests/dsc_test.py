
from PKD.db_models import SessionLocal, DSCertificate


def test_dsc():
    with SessionLocal() as session:
        # Small test
        is_revoked = 0
        DSCs = session.query(DSCertificate).all()
        for ds in DSCs:
            if ds.revoking_crl_id != None:
                print(f"DS Certificate found for {ds.country.code}, {ds.sha256_finger} with CSCA {ds.csca_id} and CRL {ds.revoking_crl_id} is revoked")
                is_revoked +=1
            if ds.issuing_csca == None:
                #print(f"DS Certificate found for {ds.country.code} has no matching CSCA")
                continue
            elif ds.issuing_csca.score == 0:
                print(f"DS Certificate found for {ds.country.code}, {ds.finger_print} with CSCA {ds.csca_id} has red trust score")
        
        print(f"There are {is_revoked} DSCs revoked")

test_dsc()