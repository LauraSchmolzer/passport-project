"""
Docstring for PKD.load_MLs.mls
"""

from dataclasses import dataclass
from enum import Enum

class HashSource(Enum):
    WEBPAGE = "webpage"
    NONE = "none"

@dataclass(frozen=True)
class MasterListSource:
    code: str
    name: str
    ml_url: str
    hash_url: str | None
    hash_source: HashSource


SOURCES: list[MasterListSource] = [
    MasterListSource(
        code="NL",
        name="Netherlands",
        ml_url="https://www.npkd.nl/files/ml/NL_MASTERLIST.mls",
        hash_url="https://www.npkd.nl/masterlist.html",
        hash_source=HashSource.WEBPAGE,
    ),
    MasterListSource(
        code="DE",
        name="Germany",
        ml_url="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile",
        hash_url=None,
        hash_source=HashSource.NONE,
    ),
    MasterListSource(
        code="IT",
        name="Italy",
        ml_url="https://csca-ita.interno.gov.it/certificatiCSCA/IT_MasterListCSCA.zip",
        hash_url=None,
        hash_source=HashSource.NONE,
    ),
]