
from asn1crypto import x509 as asn1_x509
from asn1crypto import crl as asn1_crl

from cryptography import x509 # Use cryptography version 46
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes

import logging
logger = logging.getLogger(__name__)

_HASH_ALGOS = {
    "sha1":     hashes.SHA1(),
    "sha224":   hashes.SHA224(),
    "sha256":   hashes.SHA256(),
    "sha384":   hashes.SHA384(),
    "sha512":   hashes.SHA512(),
}

def _verify_signature_generic(
    tbs_bytes: bytes,
    signature: bytes,
    hash_name: str,
    sig_algo: str,
    issuer_pubkey,
    asn1_obj=None,  # only needed for RSA-PSS param extraction
) -> bool:

    hash_alg = _HASH_ALGOS.get(hash_name)
    if hash_alg is None:
        raise ValueError(f"Unsupported hash algorithm: {hash_name}")

    try:
        if isinstance(issuer_pubkey, rsa.RSAPublicKey):
            if sig_algo == "rsassa_pss":
                logger.debug("RSA-PSS signature detected")
                params = asn1_obj["signature_algorithm"]["parameters"] if asn1_obj else None
                salt_length = params["salt_length"].native if params else 20
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
            logger.error("Unsupported key type", extra={"type": str(type(issuer_pubkey))})
            return False
        logger.debug("Signature verification successful")
        return True
    except InvalidSignature:
        logger.debug("Signature verification unsuccessful")
        return False


def verify_crl_signature(raw: bytes, issuer_pubkey) -> bool:
    crl = x509.load_der_x509_crl(raw)
    asn1_obj = asn1_crl.CertificateList.load(raw)

    sig_alg   = asn1_obj['signature_algorithm']  
    hash_name = sig_alg.hash_algo             
    sig_algo  = sig_alg.signature_algo           


    logger.debug(
        "Verifying CRL signature",
        extra={
            "hash_algo": hash_name,
            "sig_algo": sig_algo,
        }
    )

    return _verify_signature_generic(
        tbs_bytes     = crl.tbs_certlist_bytes,
        signature     = crl.signature,
        hash_name     = hash_name,
        sig_algo      = sig_algo,
        issuer_pubkey = issuer_pubkey,
        asn1_obj      = asn1_obj,
    )

def verify_signature(raw: bytes, issuer_pubkey) -> bool:
    cert = x509.load_der_x509_certificate(raw)
    asn1_cert = asn1_x509.Certificate.load(raw)

    logger.debug(
        "Verifying DS certificate signature",
        extra={
            "hash_algo": asn1_cert.hash_algo,
            "sig_algo":  asn1_cert.signature_algo,
        }
    )

    return _verify_signature_generic(
        tbs_bytes     = cert.tbs_certificate_bytes,
        signature     = cert.signature,
        hash_name     = asn1_cert.hash_algo,
        sig_algo      = asn1_cert.signature_algo,
        issuer_pubkey = issuer_pubkey,
        asn1_obj      = asn1_cert,
    )