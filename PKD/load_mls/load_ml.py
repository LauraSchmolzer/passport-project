import requests
import hashlib
from io import BytesIO
from zipfile import ZipFile
import certifi
from typing import Iterator
from bs4 import BeautifulSoup

from dataclasses import dataclass
from PKD.load_mls.mls import SOURCES, HashSource, MasterListSource

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
    response = requests.get(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=30,
        verify=certifi.where(),
    )
    response.raise_for_status()
    return response.content

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

def find_sha256(source: MasterListSource) -> str:
    html = fetch(source.hash_url)
    soup = BeautifulSoup(html, "html.parser")
    for p in soup.find_all('p'):
        if 'SHA-256' in p.text:
            # The hash is in the next blockquote sibling
            blockquote = p.find_next('blockquote')
            return blockquote.find('p').text.strip()
    
    raise ValueError(f"Could not find SHA-256 on {source.name} page")


#__________ Load all MasterLists ______________________________________________________________________
def load_mls() -> Iterator[ParsedML]:
    for source in SOURCES:
        raw = fetch(source.ml_url)
        raw = unzip_if_needed(raw)

        raw_sha = sha256(raw)

        if source.hash_source == HashSource.WEBPAGE:
            web_sha = find_sha256(source)
            hash_check = (web_sha == raw_sha)
        else:
            hash_check = None

        yield ParsedML(
            country=source.code,
            raw=raw,
            sha256_finger=raw_sha,
            hash_check=hash_check
        )
