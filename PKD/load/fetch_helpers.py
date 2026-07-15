"""
    Helper functions for fetching url
"""
import requests
from io import BytesIO
from zipfile import ZipFile
import certifi
import time

import logging
logger = logging.getLogger(__name__)

MAX_RETRIES = 5
BACKOFF = 2

def fetch(url: str) -> bytes:
    for attempt in range(MAX_RETRIES):

        logger.info("Try fetch %s attempt %s",url, attempt)

        try:
            response = requests.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=30,
                verify=certifi.where(),
            )
            response.raise_for_status()
            return unzip_if_needed(response.content)
        
        except (requests.ConnectionError, requests.Timeout) as e:
            logger.debug("Recoverable network error :%s", e)
            if attempt <   MAX_RETRIES - 1:
                sleep_time = 2 ** (attempt + 1)
                time.sleep(sleep_time)
        
        except requests.HTTPError as e:
            if e.response is not None and 500 <= e.response.status_code < 600:
                logger.debug("Recoverable server error: %s", e)
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** (attempt + 1)) 
                    continue
            logger.debug("Unrecoverable HTTP error: %s for %s", e, url)
            raise
        
        except requests.RequestException as e:
            logger.debug("Unrecoverable HTTP error: %s for %s", e, url)
            raise 
    else:
        raise Exception(f"Failed to fetch data for {url} in {MAX_RETRIES} attempts.")


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

