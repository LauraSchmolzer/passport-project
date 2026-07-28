eMRTD_participants = {
    'AD', 'AE', 'AG', 'AL', 'AM', 'AO', 'AR', 'AT', 'AU', 'AZ',
    'BA', 'BB', 'BD', 'BE', 'BG', 'BH', 'BJ', 'BM', 'BR', 'BS',
    'BW', 'BY', 'BZ', 'CA', 'CH', 'CI', 'CL', 'CM', 'CN', 'CO',
    'CR', 'CY', 'CZ', 'DE', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE',
    'EG', 'ES', 'ET', 'EU', 'FI', 'FR', 'GB', 'GE', 'GH', 'GM',
    'GR', 'HR', 'HU', 'ID', 'IE', 'IL', 'IN', 'IQ', 'IR', 'IS',
    'IT', 'JM', 'JO', 'JP', 'KE', 'KG', 'KN', 'KP', 'KR', 'KS',
    'KW', 'KZ', 'LB', 'LI', 'LT', 'LU', 'LV', 'MA', 'MC', 'MD',
    'ME', 'MK', 'MN', 'MT', 'MV', 'MX', 'MY', 'MZ', 'NA', 'NG',
    'NL', 'NO', 'NP', 'NZ', 'OM', 'PA', 'PE', 'PH', 'PK', 'PL',
    'PS', 'PT', 'PY', 'QA', 'RO', 'RS', 'RU', 'RW', 'SA', 'SC',
    'SD', 'SE', 'SG', 'SI', 'SK', 'SL', 'SM', 'SN', 'SY', 'TG',
    'TH', 'TJ', 'TL', 'TM', 'TR', 'TW', 'TZ', 'UA', 'UG', 'UN',
    'US', 'UY', 'UZ', 'VA', 'VC', 'VN', 'XO', 'YE', 'ZW', 'ZZ'
}

from PKD.db_models import CSCACertificate, SessionLocal, MasterList, DSCertificate
from PKD.verify.verify_cert import is_within_validity

def test_which_countries():
    with SessionLocal() as session:
        all_mls = session.query(MasterList).all()
        for ml in all_mls:
            countries = set()
            for cert in ml.csca_certs:
                countries.add(cert.country.code)

            print(f"Master list : {ml.country.code} contains {sorted(countries)}" )
            print("\n")
            

def test_missing_countries():
    countries = set()
    with SessionLocal() as session:
        all_certs = session.query(CSCACertificate).all()
        for cert in all_certs:
            countries.add(cert.country.code)

    missing = eMRTD_participants.difference(countries)
    print("="*70)
    print(f"Missing countries {sorted(missing), len(missing)} from total {len(eMRTD_participants)}")
    print("="*70)


def test_expired_certificates():
    with SessionLocal() as session:
        all_certs = session.query(DSCertificate).all()

        expired = [c for c in all_certs if not is_within_validity(c.not_before, c.not_after)]

        print("="*70)
        for cert in expired:
            print(f"  {cert.country.code, cert.signature_valid}: valid {cert.not_before} to {cert.not_after} "
                  f"(subject: {cert.subject_dn})")
        print(f"Expired or not-yet-valid CSCA certificates: {len(expired)} out of {len(all_certs)}")
        print("="*70)

#test_which_countries()

#test_missing_countries()

test_expired_certificates()