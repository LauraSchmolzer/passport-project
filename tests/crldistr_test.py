from PKD.db_models import SessionLocal, CSCACertificate
from CRL.get_URL import get_crl_urls
from CRL.fetch_crl import fetch_crl


def test_ds_crl_serial_check():
    with SessionLocal() as session:
        csca_certs = session.query(CSCACertificate).all()

        print(f"\n================ CRL FETCH ({len(csca_certs)} DS certs) ================\n")

        no_crl_dp = 0
        countries = set()
        crl_dp = 0
            
        for ds in csca_certs:
            if ds.country.code in countries:
                continue
 
            urls = get_crl_urls(ds) or []
    
            if not urls:
                no_crl_dp += 1
            else:
                url, data = fetch_crl(urls)
                if not data:
                    no_crl_dp += 1
                else:
                    crl_dp +=1
                    countries.add(ds.country.code)
        print(countries)
        
        print(f"Has crl dp {crl_dp}, has no crl dp {no_crl_dp}")
            

test_ds_crl_serial_check()