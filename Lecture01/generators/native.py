import configparser
from typing import Union

from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from datetime import datetime, timedelta
import pathlib

from sanitize_filename import sanitize

from Lecture01.generators.generator import CertificateGenerator
from common.utils import get_project_root, one_day


class NativeCertificateGenerator(CertificateGenerator):
    def __init__(self, output_directory: str = "certs"):
        super().__init__(output_directory)
        self.ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.ca_name = self.generate_name("CA")
        self.ca_certificate: Union[Certificate, None] = None

    def generate_ca_certificate(self):
        # Generate CA's certificate
        self.passphrases["CA"] = self.generate_password("CA Cert")
        ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.today() - one_day())
            .not_valid_after(datetime.today() + timedelta(days=10 * 365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        # Save CA's key and certificate
        (ca_private_key_pem, ca_cert_pem) = (
            self.ca_private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                BestAvailableEncryption(self.passphrases.get("CA").encode())
            ),
            ca_certificate.public_bytes(Encoding.PEM),
        )

        self.output_dir.joinpath("ca_private_key.pem").write_bytes(ca_private_key_pem)
        self.output_dir.joinpath("ca_certificate.pem").write_bytes(ca_cert_pem)
        self.ca_certificate = ca_certificate

    def generate_certificate(self, name):
        # Server/client's information
        self.passphrases[name] = self.generate_password(f"{name} Cert")

        server_name = self.generate_name(name)

        # At this point, if the name has been generated it means the config is present
        if not server_name:
            return False

        s_name = sanitize(name)

        # Generate server/client's private key
        server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate server/client's certificate
        server_certificate = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(self.ca_certificate.subject)
            .public_key(server_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.today() - one_day())
            .not_valid_after(datetime.today() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.get_dns_name(name))]),
                critical=False,
            )
            .sign(self.ca_private_key, hashes.SHA256())
        )

        # Save server's key and certificate
        (server_private_key_pem, server_cert_pem) = (
            server_private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            ),
            server_certificate.public_bytes(Encoding.PEM),
        )

        self.output_dir.joinpath(f"{s_name}_server_private_key.pem").write_bytes(server_private_key_pem)
        self.output_dir.joinpath(f"{s_name}_server_certificate.pem").write_bytes(server_cert_pem)

