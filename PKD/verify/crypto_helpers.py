
from PKD.db_models import CSCACertificate
from asn1crypto import x509 as asn1_x509

import subprocess
from cryptography import x509 # Use cryptography version 46
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import logging
logger = logging.getLogger(__name__)

_HASH_ALGOS = {
    "sha1":     hashes.SHA1(),
    "sha224":   hashes.SHA224(),
    "sha256":   hashes.SHA256(),
    "sha384":   hashes.SHA384(),
    "sha512":   hashes.SHA512(),
}


def _get_aki_ski(cert: asn1_x509.Certificate) -> tuple[bytes | None, bytes | None]:
    """
        Document 12: Table 6 on page 41 : Certificate Extensions Profile
            - SKI and AKI have mandatory presence for CSCA self-signed root.
            - SKI and AKI have mandatory presence for CSCA Link.
    """
    extensions = cert['tbs_certificate']['extensions']

    aki = None
    ski = None
    for ext in extensions:
        try:
            if ext['extn_id'].native == 'key_identifier':
                ski = ext['extn_value'].parsed.native
            elif ext['extn_id'].native == 'authority_key_identifier':
                aki_field = ext['extn_value'].parsed['key_identifier']
                aki = aki_field.native if aki_field else None
        except ValueError:
            logger.warning("Malformed extension encountered")
            continue  # malformed extension bytes; skip just this one

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
    
def _verify_link(link_cert: CSCACertificate, old_csca_cert: CSCACertificate) -> bool:
    # Verify link certs signature against its claimed issuer's puplic key

    issuer_pubkey = _get_publickey(old_csca_cert)
    
    raw = link_cert.raw_cert
    cert = x509.load_der_x509_certificate(raw)
    asn1_cert = asn1_x509.Certificate.load(raw)

    tbs_bytes = cert.tbs_certificate_bytes
    signature = cert.signature

    hash_name = asn1_cert.hash_algo        
    sig_algo  = asn1_cert.signature_algo   
    hash_alg = _HASH_ALGOS.get(hash_name)

    logger.debug(
        "Verifying link certificate",
        extra={
            "link_cert_id": link_cert.id,
            "issuer_id": old_csca_cert.id,
            "hash_algo": hash_name,
            "sig_algo": sig_algo,
        }
    )
    if hash_alg is None:
        raise ValueError(f"Unsupported hash algorithm: {hash_name}")

    # Find out which algorithm is used: EC or RSA
    try:
        if isinstance(issuer_pubkey, rsa.RSAPublicKey):
            if sig_algo == "rsassa_pss":
                logger.debug("RSA-PSS signature detected")

                params = asn1_cert["signature_algorithm"]["parameters"]
                salt_length = params["salt_length"].native if params else 20  # RFC 8017 default
                issuer_pubkey.verify(
                    signature, tbs_bytes,
                    padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=salt_length),
                    hash_alg,
                )
            else:
                logger.debug("RSA-PKCS1v1.5 signature detected")
                issuer_pubkey.verify(signature, tbs_bytes, padding.PKCS1v15(), hash_alg)
        elif isinstance(issuer_pubkey, ec.EllipticCurvePublicKey):
            logger.debug("ECDSA signature detected")
            issuer_pubkey.verify(signature, tbs_bytes, ec.ECDSA(hash_alg))
        else:
            logger.error(
            "Unsupported key type",
                extra={"type": str(type(issuer_pubkey))}
            )
            return False
        logger.debug("Signature verification succesful")
        return True
    except InvalidSignature:
        logger.debug("Signature verification unsuccesful")
        return False


