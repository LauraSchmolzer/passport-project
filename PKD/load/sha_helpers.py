"""
    Helpers for hashing and fetching hashes and specific parsers for SE and NL
"""
from bs4 import BeautifulSoup
import re
import hashlib

from PKD.load.mls import MasterListSource
from PKD.load.fetch_helpers import fetch

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
    
def find_sha(source: MasterListSource) -> str:
    # Because websites have different structures, specific parsers are needed
    if source.code == "NL":
        return find_sha_NL(source)
    elif source.code == "SE":
        return find_sha_SE(source)

def find_sha_NL(source: MasterListSource) -> str:
    html = fetch(source.hash_url)
    soup = BeautifulSoup(html, "html.parser")

    for p in soup.find_all('p'):
        if 'SHA-256' in p.text:                           
            # The hash is in the next blockquote sibling
            blockquote = p.find_next('blockquote')
            return blockquote.find('p').text.strip()

    raise ValueError(f"Could not find SHA on {source.code} page")

def find_sha_SE(source: MasterListSource) -> str:
    html = fetch(source.hash_url)
    soup = BeautifulSoup(html, "html.parser")

    text = soup.get_text("\n")

    m = re.search(
        r"SWE\.ml\s+SHA1:\s*([a-f0-9]{40})",
        text,
        re.IGNORECASE | re.DOTALL,
    )

    if m:
        return m.group(1)

    raise ValueError(f"Could not find SHA on {source.name} page")

