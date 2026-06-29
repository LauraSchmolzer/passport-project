
"""
Docstring of CRLs
"""

from dataclasses import dataclass
from enum import Enum

@dataclass(frozen=True)
class CRLSource:
    code: str
    organisation: str
    crl_url: str


CRL_SOURCES: list[CRLSource] = [
    CRLSource(
        code="EU",
        organisation="European Union",
        crl_url="https://eu-csca.jrc.ec.europa.eu",
    ),
    CRLSource(
        code="AU",
        organisation="GOC OU",
        crl_url="https://www.passports.gov.au/sites/default/files/documents/2026-05/59.crl",
    ),
    CRLSource(
        code="GR",
        organisation="Hellenic Republic",
        crl_url="https://www.passport.gov.gr/components/com_content/plugins/download/includes/dl.php?c=ADANKgQ5CDlXfgQ3UyUFMQIpC3YNa1FtUDAMblQxCzZXYw80VWE=&m=0",
    ),
    CRLSource(
        code="NL",
        organisation="Kingdom of the Netherlands",
        crl_url="http://crl.pkioverheid.nl/RootLatestCRL-G3.crl",
    ),
    CRLSource(
        code="DE",
        organisation="bund",
        crl_url="http://download.gsb.bund.de/BSI/crl/DE_CRL.crl",
    ),  
    
]