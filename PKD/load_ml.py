import requests
import hashlib
from io import BytesIO
from zipfile import ZipFile
import certifi
from typing import Iterator
from bs4 import BeautifulSoup
from dataclasses import dataclass
from enum import Enum

class HashSource(Enum):
    WEBPAGE = "webpage"  # hash must be parsed from a webpage
    NONE = "none"

# Country consists of URL to ML and URL to hash (some have to be parsed differently)
class URLS(Enum):
    NL = ('https://www.npkd.nl/files/ml/NL_MASTERLIST.mls', 
          'https://www.npkd.nl/masterlist.html',
          HashSource.WEBPAGE, "Netherlands")
    DE = ('https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile',
         None,
         HashSource.NONE, "Germany")
    IT = ('https://csca-ita.interno.gov.it/certificatiCSCA/IT_MasterListCSCA.zip', 
          None,
          HashSource.NONE, "Italy")

@dataclass
class ParsedML:
    country : str
    raw: bytes
    sha256_finger: str
    hash_check: bool | None

#__________ Helper functions ______________________________________________________________________

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    try:
        response = requests.get(
            url,
            headers={'User-Agent': 'Mozilla/5.0'},
            timeout=30,
            verify=certifi.where()
        )
        response.raise_for_status()
        return response.content
    except:
        print(f"Could not fetch for {url}")
        return None

def unzip_if_needed(data: bytes) -> bytes:
    if not data.startswith(b"PK"):
        return data

    with ZipFile(BytesIO(data)) as z:
        for name in z.namelist():
            if name.lower().endswith((".ml", ".mls", ".ldif")):
                return z.read(name)

        # fallback: return first file
        first = z.namelist()[0]
        return z.read(first)

def find_sha256(country: URLS) -> str:
    html = fetch(country.value[1])
    soup = BeautifulSoup(html, "html.parser")
    for p in soup.find_all('p'):
        if 'SHA-256' in p.text:
            # The hash is in the next blockquote sibling
            blockquote = p.find_next('blockquote')
            return blockquote.find('p').text.strip()
    
    raise ValueError(f"Could not find SHA-256 on {country.value[3]} page")


#__________ Load all MasterLists ______________________________________________________________________
def load_mls() -> Iterator[ParsedML]:
    for c in URLS:
        country = c.value[3]
        raw = fetch(c.value[0])
        raw = unzip_if_needed(raw)
        raw_SHA = sha256(raw)
    
        if c.value[2] == HashSource.WEBPAGE:
            web_SHA = find_sha256(c)
            hash_check = (web_SHA == raw_SHA)
        else:
            hash_check = None
    

        yield ParsedML(country=country.upper(), raw=raw, sha256_finger=raw_SHA, hash_check=hash_check)
    
        
