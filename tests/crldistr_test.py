
from PKD.db_models import SessionLocal, CSCACertificate
from PKD.CRL.get_crl import GetCRL

INCLUDE_ICAO = False


def test_ds_crl_serial_check():
    with SessionLocal() as session:
        csca_certs = session.query(CSCACertificate).all()

        getter = GetCRL(session)

        print("\n" + "=" * 70)
        print(f"{'CRL FETCH CHECK':^70}")
        print("=" * 70)
        print(f"Total CSCA certificates: {len(csca_certs)}\n")

        checked_countries = set()
        verified_countries = set()
        failed_countries = set()

        duplicate_cert_countries = set()

        for csca in csca_certs:
            country = csca.country.code

            # Detect multiple CSCA certs per country
            if country in checked_countries:
                duplicate_cert_countries.add(country)
                continue

            checked_countries.add(country)

            result = getter.get_crl(csca, INCLUDE_ICAO)

            if result is None:
                failed_countries.add(country)
            else:
                raw, signing_csca = result
                verified_countries.add(country)

        print("-" * 70)
        print(f"{'RESULTS':^70}")
        print("-" * 70)

        total_countries = len(checked_countries)
        success = len(verified_countries)
        failed = len(failed_countries)

        print(f"Countries checked : {total_countries}")
        print(
            f"CRL verified      : {success} "
            f"({success / total_countries * 100:.1f}%)"
            if total_countries else "CRL verified      : 0"
        )
        print(
            f"No CRL found      : {failed} "
            f"({failed / total_countries * 100:.1f}%)"
            if total_countries else "No CRL found      : 0"
        )

        print("\n" + "-" * 70)
        print(f"{'COUNTRIES WITH VERIFIED CRL':^70}")
        print("-" * 70)
        print(", ".join(sorted(verified_countries)) or "None")

        print("\n" + "-" * 70)
        print(f"{'COUNTRIES WITHOUT VERIFIED CRL':^70}")
        print("-" * 70)
        print(", ".join(sorted(failed_countries)) or "None")



test_ds_crl_serial_check()
            