"""
    Find all CRL Distribution points    
"""

from asn1crypto import x509 as asn1_x509
from typing import Optional

from CRL.build_URL import get_crl_distribution_urls, get_country_code, build_pkd_crl_urls
from PKD.db_models import CSCACertificate
from CRL.two_to_three import two_to_three

import logging
logger = logging.getLogger(__name__)

def get_crl_urls(ds_cert: CSCACertificate) -> Optional[str]:

    urls = []

    cert = asn1_x509.Certificate.load(ds_cert.raw_cert)
    extn_urls = get_crl_distribution_urls(cert)
    if extn_urls:
        urls.extend(extn_urls)
    
    state_code, local_code = get_country_code(cert)
    if not local_code:
        local_code= two_to_three(ds_cert.country.code)
    if state_code and (state_code != local_code):
        urls.extend(build_pkd_crl_urls(f"{local_code}_{state_code}"))
    if local_code:
        urls.extend(build_pkd_crl_urls(local_code))
    
    if urls:
        logger.info("Found %s URLs", len(urls))
        return urls
    
    logger.debug("No URLS found for %s", ds_cert.country.code)
    return None
    

    


