"""
    Here we score the trust level of a certificate.
"""

from PKD.db_models import CSCACertificate, CSCALink, DSCertificate
from sqlalchemy import or_
from enum import Enum

""" From the official documentation - https://www.icao.int/icao-pkd/epassport-validation-roadmap-tool-validating-csca 

    ================= GREEN =================
    -   It has been successfully cryptographically back-checked with a link certificate against the previous CSCA; 
    -   It has been acquired by hand from known persons at a trusted diplomatic source such as an embassy;
    -   It has been cross checked by two or more of the following:
        -   it has been acquired by hand from known persons at a trusted source (such as a representative at a PKD meeting);
        -   it can be cross-checked via a separate route
            -   appears in other PKD published Masterlists;
            -   authenticates DSCs published on the PKD/in multiple passports;
            -   the thumbprint cross checks against another source such as an email via ICAO or what is published on an official website.
    
    ================= AMBER =================
    -   It was received via a known route (e.g. standards meeting), but no cross-checking
    -   If CSCA Certificate is found to successfully authenticate new travel documents from the issuing State or the thumbprint
        from unsuccessful authentications can be cross-checked, the CSCA Certificate may be upgraded to a green rating.

    ================= RED =================
    -   For example, the CSCA Certificate has been downloaded from a publicly accessible website or
        was received by email with no other information received via a separate route against which to cross-check. 
"""

class TrustLevel(Enum):
    RED = 0
    AMBER = 1
    GREEN = 2
    
class ScoreCSCABuilder:
    def __init__(self, session):
        self.session = session
    
    def score(self):
        csca_certs = (self.session.query(CSCACertificate).filter_by(is_link_cert=False).all())

        for csca_cert in csca_certs:
            self._score(csca_cert)

    def _score(self, csca_cert: CSCACertificate):
        score = 0

        if self.has_links(csca_cert):
            score += 1
        if self.has_dscs(csca_cert):
            score += 1
        if self.multiple_mls_2(csca_cert):
            score +=1
        if self.multiple_mls_5(csca_cert):
            score +=1
        
        csca_cert.score = score
        self.session.add(csca_cert)
            

    def has_links(self,csca_cert: CSCACertificate) -> bool:
        links = (
            self.session.query(CSCALink)
            .filter(
                    or_(CSCALink.from_csca_id==csca_cert.id,
                    CSCALink.to_csca_id==csca_cert.id)
            )
            .all()
        )
        return len(links) > 0
    
    def multiple_mls_2(self,csca: CSCACertificate) -> bool:
        return len(csca.master_lists) >= 2
    
    def multiple_mls_5(self,csca: CSCACertificate) -> bool:
        return len(csca.master_lists) >= 5

    def has_dscs(self,csca_cert: CSCACertificate) -> bool:
        dscs = (
            self.session.query(DSCertificate)
            .filter(
                    or_(DSCertificate.csca_id==csca_cert.id)
            )
            .all()
        )
        return len(dscs) > 1