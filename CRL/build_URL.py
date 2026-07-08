"""
    Help functions build the CRL distribution points   
"""
from asn1crypto import x509 as asn1_x509
from typing import List, Optional
from urllib.parse import urlparse

import logging
logger = logging.getLogger(__name__)


def get_extension_native(cert: asn1_x509.Certificate, extn_name: str) -> Optional[str]:
    # Find specific extension
    ext = cert['tbs_certificate']['extensions']
    if not ext:
        logger.debug("No extensions found")
        return None
 
    for e in ext:
        if e['extn_id'].native == extn_name:
            return e['extn_value'].native
        
    logger.debug("Specific extension %s not found", extn_name)
    return None

def build_pkd_crl_urls(country_code: str) -> List[str]:
    return [
        f"https://pkddownload1.icao.int/CRLs/{country_code}.crl",
        f"https://pkddownload2.icao.int/CRLs/{country_code}.crl",
    ]

# Some URLs in the extension are just 'http://' or 'htttps://', which is obviously invalid
def is_valid_url(url: str) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in ('http', 'https') and bool(parsed.netloc)


"""
    OID: 2.5.29.31
    Name: crl_distribution_points
    Critical: False
    Value: [OrderedDict([('distribution_point', ['http://www.bmi.gv.at/csca/crl/CSCAAUSTRIA.crl']), ('reasons', None), ('crl_issuer', None)])]
"""

def get_crl_distribution_urls(cert: asn1_x509.Certificate) -> Optional[str]:

    crl_extn = get_extension_native(cert, 'crl_distribution_points')

    if not crl_extn:
        return []
    
    urls: List[str] = []
    for point in crl_extn:
        distr_point = point.get('distribution_point')
        print(distr_point)
        if not distr_point:
            continue
        for name in distr_point:
            if is_valid_url(name):
                logger.info("HTTPS/HTTP entry: %s", name)
                urls.append(name)
            elif isinstance(name, str) and name.startswith('ldap://'):
                logger.info("LDAP entry: %s", name)
                urls.append(name)
    return urls

"""
    OID: 2.5.29.18
    Name: issuer_alt_name
    Critical: False
    Value: ['lssservice@mfa.gov.cn', OrderedDict([('locality_name', 'CHN'), ('state_or_province_name', 'CHN')])]
"""
    
def get_country_code(cert: asn1_x509.Certificate) -> tuple[str | None, str] | None:
    code_extn = get_extension_native(cert, 'issuer_alt_name')

    if not code_extn:
        return None, None
    
    for entry in code_extn:
        if not isinstance(entry, dict):
            continue
        locality = entry.get('locality_name')
        state = entry.get('state_or_province_name')
        if locality is None:
            continue
        if state:
            return state, locality
        return None, locality
    return None, None

