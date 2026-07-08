"""
    Map ISO country two letter code to three letter code: NO -> NOR
"""
from __future__ import annotations
from typing import Optional
 
import pycountry
 
# Three letter code for organisations that are not in pycountry
ALPHA2_OVERRIDES = {
    "EU": "EUE",   
    "UN": "UNO",  
    "ZZ": None, 
    "XO": "XOM", # Unverified
    "KS": "RKS",
}

def two_to_three(code: Optional[str]) -> Optional[str]:

    if not code:
        return None
 
    code = code.strip().upper()
 
    if code in ALPHA2_OVERRIDES:
        mapped = ALPHA2_OVERRIDES[code]
        return mapped
 
    country = pycountry.countries.get(alpha_2=code)
    if country is None:
        return None
 
    return country.alpha_3
 
