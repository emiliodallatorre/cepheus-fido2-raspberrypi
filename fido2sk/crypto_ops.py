from hashlib import sha256
import datetime

import cbor2
from ecdsa import SigningKey, NIST256p
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend


def generate_cryptographic_keys(secret_string):
    hash_of_secret = sha256(secret_string.encode()).digest()
    private_key = SigningKey.from_string(hash_of_secret[:32], curve=NIST256p)
    public_key = private_key.get_verifying_key()
    pvtkeystr = private_key.to_string().hex()

    if public_key is None:
        raise Exception("Public key generation failed")
    pubkeystr = public_key.to_string().hex()
    return pvtkeystr, pubkeystr


def to_cose_key(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    public_key = private_key.get_verifying_key()

    if public_key is None:
        raise Exception("Public key generation failed")
    pubkeystr = public_key.to_string().hex()
    public_key_bytes = bytes.fromhex(pubkeystr)
    x = public_key_bytes[:32]
    y = public_key_bytes[32:]
    cose_key = {
        1: 2,
        3: -7,
        -1: 1,
        -2: x,
        -3: y,
    }
    return cbor2.dumps(cose_key)


def get_algo():
    return -7


def sign_challenge(pvtkey, challenge):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes = private_key.to_der()
    private_key = load_der_private_key(
        private_key_bytes, password=None, backend=default_backend()
    )
    return private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))


def gen_certificate(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes = private_key.to_der()
    private_key = load_der_private_key(
        private_key_bytes, password=None, backend=default_backend()
    )
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "WB"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kolkata"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AdityaMitra"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )

    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.public_key(public_key)
    builder = builder.not_valid_before(
        datetime.datetime.today() - datetime.timedelta(days=1)
    )
    builder = builder.not_valid_after(
        datetime.datetime.today() + datetime.timedelta(days=365)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def hash_data(data):
    return sha256(data).digest()
