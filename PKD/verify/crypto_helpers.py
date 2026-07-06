
from PKD.db_models import CSCACertificate
from asn1crypto import x509 as asn1_x509
from asn1crypto import crl as asn1_crl

import subprocess
from cryptography import x509 # Use cryptography version 46
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key

import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import logging
logger = logging.getLogger(__name__)

def _get_aki_ski(cert: asn1_x509.Certificate | asn1_crl.CertificateList, extension_field = 'extensions', cert_field = 'tbs_certificate') -> tuple[bytes | None, bytes | None]:
    """
        Document 12: Table 6 on page 41 : Certificate Extensions Profile
            - SKI and AKI have mandatory presence for CSCA self-signed root.
            - SKI and AKI have mandatory presence for CSCA Link.
    """
    extensions = cert[cert_field][extension_field]

    aki = None
    ski = None
    for ext in extensions:
        try:
            if ext['extn_id'].native == 'key_identifier':
                ski = ext['extn_value'].parsed.native
            elif ext['extn_id'].native == 'authority_key_identifier':
                aki_field = ext['extn_value'].parsed['key_identifier']
                aki = aki_field.native if aki_field else None
        except (ValueError, KeyError, TypeError):
            logger.warning("Malformed extension encountered")
            continue # malformed extension bytes; skip just this one

    return aki, ski

def _get_publickey(c: CSCACertificate):
    # ICAO 9303 requires CSCA/DC certificates to encode EC public keys with explicit curve parameters
    # Cryptography library refuses top load this design
    raw = c.raw_cert
    try:
        cert = x509.load_der_x509_certificate(raw)
    except Exception as e:
        logger.error("Failed to load DER certificate",
            extra={
                "error": str(e),
                "cert_size": len(raw),})
        raise ValueError("Failed to extract public key")

    try: 
        return cert.public_key() # first try with cryptography library 
    except Exception as e: # else reformat
        if "explicit" not in str(e).lower():
            logger.exception("Unexpected cryptography failure while extracting public key")
            raise  # unrelated errors, error must be about explicit curve params
        
        logger.warning("Using OpenSSL fallback for explicit EC parameters",
                       extra={"reason":"explicit_curve_parameters"})
        # re-encode to PEM bytes
        pem_cert = cert.public_bytes(Encoding.PEM) 
        # pull the public key out the the re-encoded certificate
        extract = subprocess.run(
            ["openssl", "x509", "-pubkey", "-noout"],
            input=pem_cert, capture_output=True, check=True,
        )
        # EC public key, express curve as named-curve OID, not raw explicit numbers (re-format to make compatible with library)
        converted = subprocess.run(
            ["openssl", "ec", "-pubin", "-param_enc", "named_curve", "-pubout"],
            input=extract.stdout, capture_output=True, check=True,
        )
        # load back to cryptography library who now recognizes it, regular EllipticCurvePublicKey object
        return load_pem_public_key(converted.stdout)
