""" 
    Parse the Icao PKD 
"""

### source venv/bin/activate

from ldif import LDIFParser
from asn1crypto import cms, core, x509 as asn1_x509
import os

from dotenv import load_dotenv
load_dotenv()

ICAOPKD_PATH = os.getenv('ICAOPKD_ML_PATH')


with open(ICAOPKD_PATH , "rb") as f:

    parser = LDIFParser(f)
    for dn, entry in parser.parse():
        if 'pkdMasterListContent;binary' in entry:
            # Put Distinguished Name (DN) in dict format
            parts = dict(p.strip().split('=', 1) for p in dn.split(',') if '=' in p)
            country = parts.get('c', 'unknown').upper() # Retrieve country ISO 3166
        
            ml_bytes = entry['pkdMasterListContent;binary'][0] # Bytes encoded Master List

            # Unwarp the Cryptographic Message Syntax, creates python objects
            content_info = cms.ContentInfo.load(ml_bytes)
            signed_data  = content_info['content']
            encap        = signed_data['encap_content_info']
            econtent     = encap['content']
                    
            # Parse CscaMasterList
            masterlist = CscaMasterList.load(econtent.contents)
            certs      = list(masterlist['cert_list'])

            de_ml = set()
            for cert in certs:
                c = asn1_x509.Certificate.load(cert.dump())
                subject = c.subject.native
                de_ml.add(subject.get("country_name", "").upper())
        
            print(country,": ",sorted(de_ml), len(de_ml))




            
  
                    