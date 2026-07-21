
from dataclasses import dataclass 
from ldif import LDIFParser 
from enum import Enum
import hashlib 

import logging
logger = logging.getLogger(__name__)

class RecordKind(Enum):
    DS = "ds"
    CRL = "crl"

@dataclass
class ParsedRecord:
    kind: RecordKind
    country: str
    raw: bytes
    sha256_finger: str


def sha256(data: bytes) -> str: 
    return hashlib.sha256(data).hexdigest()

def extract_country_from_dn(dn: str):
    for part in dn.split(","):
        part = part.strip()
        if part.startswith("c="):
            return part.split("=", 1)[1][:2].upper()
        elif part.startswith("C="):
            return part.split("=", 1)[1][:2].upper()
    logger.warning("No country extracted from dn")
    print(dn)
    return None

class ParseLDIF(LDIFParser):
    def process_file(self):
        for dn, entry in super().parse():

            if not entry:
                continue

            if "userCertificate;binary" in entry:
                logger.info("LDIF DS found")
                yield from self.handle_ds(dn, entry)

            elif "certificateRevocationList;binary" in entry:
                logger.info("LDIF CRL found")
                yield from self.handle_crl(dn, entry)
            
            continue
    
    def handle_ds(self, dn, entry):
        raw = entry["userCertificate;binary"][0]
        country = extract_country_from_dn(dn)
        yield ParsedRecord(
            kind=RecordKind.DS, 
            country=country, 
            raw=raw, 
            sha256_finger=sha256(raw))

    def handle_crl(self, dn, entry):
        raw = entry["certificateRevocationList;binary"][0]
        country = extract_country_from_dn(dn)
        yield ParsedRecord(
            kind=RecordKind.CRL, 
            country=country, 
            raw=raw, 
            sha256_finger=sha256(raw))