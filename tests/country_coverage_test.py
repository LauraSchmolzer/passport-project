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

from PKD.db_models import CSCACertificate, SessionLocal, MasterList

def test_which_countries():
    with SessionLocal() as session:
        all_mls = session.query(MasterList).all()
        for ml in all_mls:
            countries = set()
            for cert in ml.csca_certs:
                countries.add(cert.country.code)

            print(f"Master list : {ml.country.code} contains {sorted(countries)}" )

def test_cert_hash_integrity():
    countries = set()
    with SessionLocal() as session:
        all_certs = session.query(CSCACertificate).all()
        for cert in all_certs:
            countries.add(cert.country.code)
    
    missing = eMRTD_participants.difference(countries)
    print(f"Missing countries {sorted(missing), len(missing)} from total {len(eMRTD_participants)}")

test_cert_hash_integrity()
print("\n")
test_which_countries()