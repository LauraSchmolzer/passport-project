from asn1crypto import cms, core, x509 as asn1_x509
from PKD.load_ml import ParsedML

class CscaMasterList(core.Sequence):
    _fields = [
        ('version',   core.Integer),
        ('cert_list', core.SetOf, {'spec': asn1_x509.Certificate}),
    ]

def parse_ml(ml: ParsedML) -> list[asn1_x509.Certificate] :
    content_info = cms.ContentInfo.load(ml.raw)
    signed_data  = content_info['content']
    econtent     = signed_data['encap_content_info']['content']
    masterlist   = CscaMasterList.load(econtent.contents)
    return list(masterlist['cert_list'])


        
        
        