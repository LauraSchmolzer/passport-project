"""
    Test correctness of signature verification

    Covered: 
        - AKI/SKI extraction (including the self-signed-root-AKI-equals-own-SKI property and DS-AKI-matches-CSCA-SKI chaining), 
        - Public key extraction for both RSA and named-curve EC
        - Tampered/wrong-key/unsupported-key-type/unsupported-hash rejection paths 
        - CRL signature verification for both RSA and EC issuers with and without revoked entries
        - Explicit EC parameters fallback in _get_publickey

    Tests included:
        - TestGetAkiSki (_get_aki_ski)
        - TestGetPublicKey (_get_publickey)
        - TestVerifySignature (_verify_signature & _verify_signature_generic)
        - TestVerifyCrlSignature (_verify_crl_signature)

"""

import os
import shutil
import subprocess
import tempfile
import datetime
from types import SimpleNamespace

# python -m pytest tests/signature_test.py -v

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509.oid import NameOID

from asn1crypto import x509 as asn1_x509

from PKD.verify.crypto_helpers import get_publickey, get_aki_ski
from PKD.verify.verify_cert import (
    _verify_signature_generic,
    verify_crl_signature,
    verify_signature,
)

# ---------------------------------------------------------------------------
# Generate certificate objects
# ---------------------------------------------------------------------------

ONE_DAY = datetime.timedelta(days=1)

def now():
    return datetime.datetime.now(datetime.timezone.utc)


def name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

# Like CSCA cert
def generate_self_signed_cert(private_key, public_key, cn: str, hash_alg=hashes.SHA256()):
    # issuer == subject, AKI == SKI
    subject = issuer = name(cn)
    ski = x509.SubjectKeyIdentifier.from_public_key(public_key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - ONE_DAY)
        .not_valid_after(now() + datetime.timedelta(days=3650))
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=ski.digest,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    )
    return builder.sign(private_key, hash_alg)

# Like DS cert
def generate_issued_cert(issuer_key, issuer_cert, subject_pubkey, cn: str, hash_alg=hashes.SHA256()):
    # DS-style cert signed by a CSCA, AKI is issuers SKI
    subject_ski = x509.SubjectKeyIdentifier.from_public_key(subject_pubkey)
    issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now() - ONE_DAY)
        .not_valid_after(now() + datetime.timedelta(days=365))
        .add_extension(subject_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=issuer_ski.digest,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hash_alg)


def generate_crl(issuer_key, issuer_cert, revoked_serials=(), hash_alg=hashes.SHA256()):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now())
        .next_update(now() + datetime.timedelta(days=90))
    )
    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now())
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(issuer_key, hash_alg) # is signed by CSCA

# Certificates are DER encoded
def der(cert_or_crl) -> bytes:
    return cert_or_crl.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rsa_csca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, generate_self_signed_cert(key, key.public_key(), "Test RSA CSCA")


@pytest.fixture
def ec_csca():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, generate_self_signed_cert(key, key.public_key(), "Test EC CSCA")


@pytest.fixture
def rsa_ds_cert(rsa_csca):
    csca_key, csca_cert = rsa_csca
    ds_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return generate_issued_cert(csca_key, csca_cert, ds_key.public_key(), "Test DS")


@pytest.fixture
def ec_ds_cert(ec_csca):
    csca_key, csca_cert = ec_csca
    ds_key = ec.generate_private_key(ec.SECP256R1())
    return generate_issued_cert(csca_key, csca_cert, ds_key.public_key(), "Test DS EC")



@pytest.fixture
def explicit_ec_der_cert():
    """
    EC public key encodes explicit curve parameters instead of a named-curve OID
    """

    if shutil.which("openssl") is None:
        pytest.skip("openssl CLI not available on PATH")
 
    with tempfile.TemporaryDirectory() as tmp:
        params_path = os.path.join(tmp, "explicit_params.pem")
        key_path = os.path.join(tmp, "explicit_key.pem")
        cert_path = os.path.join(tmp, "explicit_cert.pem")
 
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1",
             "-param_enc", "explicit", "-out", params_path],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "ecparam", "-in", params_path,
             "-genkey", "-noout", "-out", key_path],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-key", key_path,
             "-out", cert_path, "-days", "365",
             "-subj", "/CN=Test Explicit EC CSCA"],
            check=True, capture_output=True,
        )
 
        return subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
 


# ---------------------------------------------------------------------------
# _get_aki_ski
# ---------------------------------------------------------------------------

class TestGetAkiSki:
    def test_extracts_ski_and_aki_from_ds_cert(self, rsa_ds_cert):
        parsed = asn1_x509.Certificate.load(der(rsa_ds_cert))
        aki, ski = get_aki_ski(parsed)
        assert aki is not None
        assert ski is not None

    def test_self_signed_root_aki_matches_own_ski(self, rsa_csca):
        _, csca_cert = rsa_csca
        parsed = asn1_x509.Certificate.load(der(csca_cert))
        aki, ski = get_aki_ski(parsed)
        # CSCA self-signed root so AKI is required to reference its own SKI
        assert aki == ski

    def test_ds_aki_matches_issuing_csca_ski(self, rsa_csca, rsa_ds_cert):
        _, csca_cert = rsa_csca
        csca_parsed = asn1_x509.Certificate.load(der(csca_cert))
        ds_parsed = asn1_x509.Certificate.load(der(rsa_ds_cert))
        _, csca_ski = get_aki_ski(csca_parsed)
        ds_aki, _ = get_aki_ski(ds_parsed)
        assert ds_aki == csca_ski

    def test_missing_extensions_returns_none_none(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name("No Extensions"))
            .issuer_name(name("No Extensions"))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now() - ONE_DAY)
            .not_valid_after(now() + ONE_DAY)
            .sign(key, hashes.SHA256())
        )
        parsed = asn1_x509.Certificate.load(der(cert))
        aki, ski = get_aki_ski(parsed)
        assert aki is None
        assert ski is None


# ---------------------------------------------------------------------------
# _get_publickey
# ---------------------------------------------------------------------------

class TestGetPublicKey:
    def test_rsa_named_curve_style_cert(self, rsa_csca):
        _, cert = rsa_csca
        stub = SimpleNamespace(raw_cert=der(cert))
        pubkey = get_publickey(stub)
        assert pubkey.public_numbers() == cert.public_key().public_numbers()

    def test_ec_named_curve_cert(self, ec_csca):
        _, cert = ec_csca
        stub = SimpleNamespace(raw_cert=der(cert))
        pubkey = get_publickey(stub)
        assert pubkey.public_numbers() == cert.public_key().public_numbers()

    def test_invalid_der_raises_valueerror(self):
        stub = SimpleNamespace(raw_cert=b"not a certificate")
        with pytest.raises(ValueError):
            get_publickey(stub)
    
    # ---- TEST explicit EC parameters ----------------------------------------------------
    """
        If 'cryptography' ever changes and stops rejecting these explicit params, 
        this test fails rather than the fallback path silently going untested.
    """
    def test_cryptography_rejects_explicit_params_directly(self, explicit_ec_der_cert):
        # _get_publickey is designed to work around teh rejection that 'cryptography' gives
        cert = x509.load_der_x509_certificate(explicit_ec_der_cert)
        with pytest.raises(Exception):
            cert.public_key()
 
    def test_explicit_ec_params_uses_openssl_fallback(self, explicit_ec_der_cert):
        stub = SimpleNamespace(raw_cert=explicit_ec_der_cert)
        pubkey = get_publickey(stub)
        assert isinstance(pubkey, ec.EllipticCurvePublicKey)
        # after the fallback teh finction should re-encode explicit params to a named OID
        assert pubkey.curve.name in ("secp256r1", "prime256v1")
 
    def test_explicit_ec_signature_still_verifies(self, explicit_ec_der_cert):
        # explicit param should still be able to verify the signature
        stub = SimpleNamespace(raw_cert=explicit_ec_der_cert)
        pubkey = get_publickey(stub)
        cert = x509.load_der_x509_certificate(explicit_ec_der_cert)
        # self-signed: the cert's own public key must verify the cert's own signature
        assert verify_signature(explicit_ec_der_cert, pubkey) is True


# ---------------------------------------------------------------------------
# _verify_signature / _verify_signature_generic
# ---------------------------------------------------------------------------

class TestVerifySignature:
    def test_valid_rsa_signature(self, rsa_csca, rsa_ds_cert):
        csca_key, _ = rsa_csca
        assert verify_signature(der(rsa_ds_cert), csca_key.public_key()) is True

    def test_valid_ec_signature(self, ec_csca, ec_ds_cert):
        csca_key, _ = ec_csca
        assert verify_signature(der(ec_ds_cert), csca_key.public_key()) is True

    def test_wrong_issuer_key_fails(self, rsa_ds_cert):
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert verify_signature(der(rsa_ds_cert), wrong_key.public_key()) is False

    def test_tampered_der_fails_or_errors(self, rsa_csca, rsa_ds_cert):
        # A tampered cert should either fail to parse, or parse and fail signature verification 
        csca_key, _ = rsa_csca
        raw = bytearray(der(rsa_ds_cert))
        raw[len(raw) // 2] ^= 0xFF
        try:
            result = verify_signature(bytes(raw), csca_key.public_key())
        except Exception:
            return
        assert result is False

    def test_unsupported_key_type_returns_false(self):
        key = ed25519.Ed25519PrivateKey.generate()
        result = _verify_signature_generic(
            tbs_bytes=b"irrelevant",
            signature=b"irrelevant",
            hash_name="sha256",
            sig_algo="ed25519",
            issuer_pubkey=key.public_key(),
        )
        assert result is False

    def test_unsupported_hash_algo_raises(self, rsa_csca):
        csca_key, _ = rsa_csca
        with pytest.raises(ValueError):
            _verify_signature_generic(
                tbs_bytes=b"data",
                signature=b"sig",
                hash_name="sha3_256",
                sig_algo="rsassa_pkcs1v15",
                issuer_pubkey=csca_key.public_key(),
            )


# ---------------------------------------------------------------------------
# _verify_crl_signature
# ---------------------------------------------------------------------------

class TestVerifyCrlSignature:
    def test_valid_crl_signature_with_revoked_entries(self, rsa_csca):
        csca_key, csca_cert = rsa_csca
        crl = generate_crl(csca_key, csca_cert, revoked_serials=[12345, 67890])
        assert verify_crl_signature(der(crl), csca_key.public_key()) is True

    def test_valid_empty_crl_signature(self, rsa_csca):
        csca_key, csca_cert = rsa_csca
        crl = generate_crl(csca_key, csca_cert, revoked_serials=[])
        assert verify_crl_signature(der(crl), csca_key.public_key()) is True

    def test_crl_wrong_key_fails(self, rsa_csca):
        csca_key, csca_cert = rsa_csca
        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        crl = generate_crl(csca_key, csca_cert)
        assert verify_crl_signature(der(crl), wrong_key.public_key()) is False

    def test_ec_crl_signature(self, ec_csca):
        csca_key, csca_cert = ec_csca
        crl = generate_crl(csca_key, csca_cert, revoked_serials=[1])
        assert verify_crl_signature(der(crl), csca_key.public_key()) is True