"""
    Helper functions for fetching url
"""
import requests
from io import BytesIO
from zipfile import ZipFile
import certifi

def fetch(url: str) -> bytes:
    response = requests.get(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=30,
        verify=certifi.where(),
    )
    response.raise_for_status()
    return unzip_if_needed(response.content)

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

