"""
    All information of public MLs
"""

from dataclasses import dataclass
from enum import Enum

class HashSource(Enum):
    WEBPAGE = "webpage"
    NONE = "none"

@dataclass(frozen=True)
class MasterListSource:
    code: str
    ml_url: str
    hash_url: str | None
    hash_version: str | None
    hash_source: HashSource


SOURCES: list[MasterListSource] = [
    MasterListSource(
        code="NL",
        ml_url="https://www.npkd.nl/files/ml/NL_MASTERLIST.mls",
        hash_url="https://www.npkd.nl/masterlist.html",
        hash_version = "sha256",
        hash_source=HashSource.WEBPAGE,
    ),
    MasterListSource(
        code="DE",
        ml_url="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile",
        hash_url=None,
        hash_version = None,
        hash_source=HashSource.NONE,
    ),
    MasterListSource(
        code="IT",
        ml_url="https://csca-ita.interno.gov.it/certificatiCSCA/IT_MasterListCSCA.zip",
        hash_url=None,
        hash_version = None,
        hash_source=HashSource.NONE,
    ),
    MasterListSource(
        code="SE",
        ml_url="http://cert.polisen.se/CSCA/SWE.ml",
        hash_url="http://cert.polisen.se/CSCA/",
        hash_version = "sha1",
        hash_source=HashSource.WEBPAGE,
    ),
    
]