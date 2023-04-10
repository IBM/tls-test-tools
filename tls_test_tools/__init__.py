# Copyright 2023 IBM All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Library implementation for all tls_test_tools lives here
"""

# Standard
from contextlib import closing
from typing import List, Optional, Tuple
import datetime
import random
import socket

# Third Party
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import alog

log = alog.use_channel("TLST")

## API #########################################################################


def open_port() -> int:
    """Look for random ports until an open one is found"""
    port = _random_port()
    while not _port_open(port):
        port = _random_port()
    return port


def get_subject(
    common_name: str = "foo.com",
    country_name: str = "US",
    state_or_province_name: str = "New Barland",
    locality_name: str = "Bazville",
    organization_name: str = "FooBar Widgets Inc.",
) -> x509.Name:
    """Get the subject object used when creating self-signed certificates. This
    will be consistent across all components, but will be tailored to the domain
    of the cluster.

    Args:
        common_name:  str
            The certificate Common Name
        country_name:  str
            The certificate Country Name
        state_or_province_name:  str
            The certificate State or Province Name
        locality_name:  str
            The certificate Locality Name (city, etc...)
        organization_name:  str
            The certificate Organization Name

    Returns:
        subject:  x508.Name
            The full subect object to use when constructing certificates
    """
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def generate_key() -> Tuple[rsa.RSAPrivateKey, str]:
    """Generate a new RSA key for use when generating TLS components

    Returns:
        key:  rsa.RSAPrivateKey
            The key object that can be used to sign certificates
        key_pem:  str
            The PEM encoded string for the key
    """
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    key_pem = key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return (key, key_pem.decode("utf-8"))


def generate_ca_cert(key: rsa.RSAPrivateKey, **subject_kwargs) -> str:
    """Generate a Certificate Authority certificate based on a private key

    Args:
        key:  rsa.RSAPrivateKey
            The private key that will pair with this CA cert
        **subject_kwargs
            Extra keyword args to pass to subject generation

    Returns:
        ca:  str
            The PEM encoded string for this CA cert
    """

    # Create self-signed CA
    log.debug("Creating CA")
    subject = get_subject(**subject_kwargs)
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10000 days
            datetime.datetime.utcnow()
            + datetime.timedelta(days=10000)
        )
        .add_extension(
            # X509v3 Basic Constraints: critical
            #     CA:TRUE
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            # X509v3 Key Usage: critical
            #     Digital Signature, Key Encipherment, Certificate Sign
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_pem = ca.public_bytes(Encoding.PEM)
    return cert_pem.decode("utf-8")


def generate_derived_key_cert_pair(
    ca_key: rsa.RSAPrivateKey,
    san_list: Optional[List[str]] = None,
    key_cert_sign: bool = False,
    expire_days: int = 1000,
    **subject_kwargs,
) -> Tuple[str, str]:
    """Generate a certificate for use in encrypting TLS traffic, derived from
    a common key

    Args:
        key:  rsa.RSAPrivateKey
            The private key that will pair with this CA cert
        san_list:  Optional[List[str]]
            List of strings to use for the Subject Alternate Name
        expire_days:  int
            Number of days to expire the certificate in
        key_cert_sign:  bool
            Whether or not to set the key_cert_sign usage bit in the generated certificate.
            This may be needed when the derived key/cert will be used as an intermediate CA
            or expected to act as a self-signed CA (e.g. with IBM elasticsearch).
            Reference: https://ldapwiki.com/wiki/KeyUsage

    Returns:
        key_pem:  str
            The pem-encoded key
        crt_pem:  str
            The pem-encoded cert
    """

    # Create a new private key for the server
    key, key_pem = generate_key()

    # Create the server certificate as if using a CSR. The final key will be
    # signed by the CA private key, but will have the public key from the
    # server's key.
    #
    # NOTE: It is not legal to use an identical Common Name for both the CA and
    #   the derived certificate. With openssl 1.1.1k, this results in an invalid
    #   certificate that fails with "self signed certificate."
    #   CITE: https://stackoverflow.com/a/19738223
    issuer_name = get_subject(**subject_kwargs)
    subject_kwargs["common_name"] = ".".join(
        [subject_kwargs.get("common_name", "foo.com"), "derived"]
    )
    subject_name = get_subject(**subject_kwargs)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(san) for san in san_list or ["localhost"]]
            ),
            critical=False,
        )
        .add_extension(
            # X509v3 Key Usage: critical
            #     Digital Signature, Key Encipherment
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            # X509v3 Extended Key Usage:
            #     TLS Web Client Authentication, TLS Web Server Authentication
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    crt_pem = cert.public_bytes(Encoding.PEM)
    return (key_pem, crt_pem.decode("utf-8"))


## Implementation Details ######################################################


def _random_port():
    """Grab a random port number"""
    return int(random.uniform(12345, 55555))


def _port_open(port: int) -> bool:
    """Check whether the given port is open"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0
