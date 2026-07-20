
from PKD.db_models import SessionLocal, CRL

INCLUDE_ICAO = False


def test_all_crls():
    with SessionLocal() as session:

        CRLs = session.query(CRL).all()
        CRLs.sort(key=lambda c: c.country.code)

        empty = 0
        countries = set()

        print(f"======== THERE ARE {len(CRLs)} CRLS IN TOTAL ===========\n")

        for crl in CRLs:
            print(f"CRL from {crl.country.code}, {crl.country.organization} with revoked {crl.revoked_serials}")

            if len(crl.revoked_serials) == 0:
                empty += 1
            
            countries.add(crl.country.code)
        
        print(f"======== THERE ARE {empty} EMPTY CRLS ===========\n")
        print(f"======== IN {sorted(countries), len(countries)} THERE EXIST NON-EMPTY CRLS ===========\n")

test_all_crls()
            