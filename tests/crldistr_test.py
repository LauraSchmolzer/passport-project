
from PKD.db_models import SessionLocal, CSCACertificate
from CRL.get_crl import GetCRL


def test_ds_crl_serial_check():
    with SessionLocal() as session:
        csca_certs = session.query(CSCACertificate).all()
        getter = GetCRL(session)

        print(f"\n================ CRL FETCH ({len(csca_certs)} CSCA certs) ================\n")

        no_crl_dp = 0
        crl_dp_verified = 0
        countries = set()

        for csca in csca_certs:
            if csca.country.code in countries:
                continue

            result = getter.get_crl(csca)

            if result is None:
                no_crl_dp += 1
            else:
                raw, signing_csca = result
                crl_dp_verified += 1
                countries.add(csca.country.code)

        print(countries)
        print(f"Verified CRL found: {crl_dp_verified}, no CRL found or verified: {no_crl_dp}")


test_ds_crl_serial_check()
            