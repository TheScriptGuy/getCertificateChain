"""
Download SSL certificate chain and save as PEM files.

This script connects to a given website, downloads its SSL certificate,
and saves it as a PEM file. If the certificate has an Authority Information
Access (AIA) extension, the script will download each certificate in the chain
and save them as PEM files as well.

"""
# Standard library imports
import glob
import os
import logging
import re
import ssl
import socket
import sys
from typing import Any, Dict, List
from urllib.request import urlopen, Request

# Third-party library imports
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

VERSION = "0.1.0"
CERT_CHAIN = []

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


# parse arguments
def parse_arguments():
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Export security rules and associated Security Profile Groups to a CSV file."
    )
    parser.add_argument(
        "--rm-ca-files",
        dest="remove_ca_files",
        action="store_true",
        help="Remove the cert files in current directory (*.crt, *.pem).",
    )
    parser.add_argument(
        "--get-ca-cert-pem",
        dest="get_ca_cert_pem",
        action="store_true",
        help="Get cacert.pem from curl.se website to help find Root CA.",
    )
    parser.add_argument(
        "--domain",
        dest="domain",
        default="www.google.com",
        help="The hostname to connect to. (default: %(default)s)",
    )
    return parser.parse_args()


class SSLCertificateChainDownloader:
    def __init__(self):
        self.cert_chain = []

    def remove_cacert_pem(self):
        """
        Remove certificate files from the current directory.
        """
        for crt_file in glob.glob("*.crt"):
            os.remove(crt_file)
        for pem_file in glob.glob("*.pem"):
            os.remove(pem_file)

    def get_cacert_pem(self):
        """
        Download the cacert.pem file from the curl.se website.
        """
        cacert_pem_url = "https://curl.se/ca/cacert.pem"
        cacert_pem_file = "cacert.pem"
        logging.info("Downloading %s to %s", cacert_pem_url, cacert_pem_file)
        with urlopen(cacert_pem_url) as response, open(
            cacert_pem_file, "wb"
        ) as out_file:
            if response.getcode() != 200:
                logging.error(
                    "Error downloading %s. HTTP status code: %s",
                    cacert_pem_url,
                    response.getcode(),
                )
                sys.exit(1)
            data = response.read()
            out_file.write(data)
        logging.info("Downloaded %s to %s", cacert_pem_url, cacert_pem_file)

    def check_domain(self) -> Dict[str, Any]:
        """
        Check and parse the domain provided by the user.

        Args:
            domain (str): The domain provided by the user.

        Returns:
            Dict[str, Any]: A dictionary containing the hostname and port.
        """
        hostname, _, port = self.domain.partition(":")
        return {"hostname": hostname, "port": int(port) if port else 443}

    def get_certificate(self, hostname: str, port: int) -> x509.Certificate:
        """
        Connect to a server and retrieve the SSL certificate.

        Args:
            hostname (str): The hostname to connect to.
            port (int): The port to connect to.

        Returns:
            x509.Certificate: The SSL certificate of the server.
        """
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssl_socket:
                    cert_pem = ssl.DER_cert_to_PEM_cert(ssl_socket.getpeercert(True))
                    cert = x509.load_pem_x509_certificate(
                        cert_pem.encode(), default_backend()
                    )
            return cert
        except ConnectionRefusedError:
            print(f"Connection refused to {hostname}:{port}")
            sys.exit(1)
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
            sys.exit(1)
        except socket.timeout:
            print(f"Connection timed out to {hostname}:{port}")
            sys.exit(1)
        except socket.gaierror:
            print(f"Hostname could not be resolved: {hostname}")
            sys.exit(1)

    def normalize_subject(self, subject: str) -> str:
        """
        Normalize the subject of a certificate.

        Args:
            subject (str): The subject of the certificate.

        Returns:
            str: The normalized subject.
        """
        return "_".join(
            part.strip()
            .replace("=", "_")
            .replace(".", "_")
            .replace(" ", "_")
            .replace(",", "_")
            for part in subject.split("/")
            if part.strip()
        )

    def save_ssl_certificate(
        self,
        ssl_certificate: x509.Certificate,
        file_name: str,
    ) -> None:
        """
        Save an SSL certificate to a file.

        Args:
            ssl_certificate (x509.Certificate): The SSL certificate to save.
            file_name (str): The file name to save the SSL certificate as.
        """
        with open(file_name, "wb") as f:
            f.write(ssl_certificate.public_bytes(encoding=serialization.Encoding.PEM))

    def write_chain_to_file(self, certificate_chain: List[x509.Certificate]) -> None:
        """
        Write a certificate chain to files.

        Args:
            certificate_chain (List[x509.Certificate]): The certificate chain to write to files.
        """
        for counter, certificate_item in enumerate(certificate_chain):
            cert_subject = certificate_item.subject.rfc4514_string()
            normalized_subject = self.normalize_subject(cert_subject)
            ssl_certificate_filename = (
                f"{len(certificate_chain) - 1 - counter}-{normalized_subject}.crt"
            )
            self.save_ssl_certificate(certificate_item, ssl_certificate_filename)

    def return_cert_aia(self, ssl_certificate: x509.Certificate) -> x509.Extensions:
        """
        Get the Authority Information Access (AIA) extension from a certificate.

        Args:
            ssl_certificate (x509.Certificate): The SSL certificate.

        Returns:
            x509.Extensions: The AIA extension or None if not found.
        """
        try:
            aia = ssl_certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            return aia
        except x509.ExtensionNotFound:
            return None

    def get_certificate_from_uri(self, uri: str) -> x509.Certificate:
        """
        Retrieve a certificate from the given URI.

        Args:
            uri (str): The URI to get the certificate from.

        Returns:
            x509.Certificate: The certificate from the URI or None if there was an error.
        """
        try:
            with urlopen(uri) as response:
                if response.getcode() != 200:
                    return None
                aia_content = response.read()
                ssl_certificate = ssl.DER_cert_to_PEM_cert(aia_content)
                cert = x509.load_pem_x509_certificate(
                    ssl_certificate.encode("ascii"), default_backend()
                )
                return cert
        except Exception:
            return None

    def return_cert_aia_list(self, ssl_certificate: x509.Certificate) -> list:
        """
        Get the list of AIA URIs from a certificate.

        Args:
            ssl_certificate (x509.Certificate): The SSL certificate.

        Returns:
            list: A list of AIA URIs.
        """
        aia_uri_list = []

        for extension in ssl_certificate.extensions:
            cert_value = extension.value

            if isinstance(cert_value, x509.AuthorityInformationAccess):
                data_aia = [x for x in cert_value or []]
                for item in data_aia:
                    if item.access_method._name == "caIssuers":
                        aia_uri_list.append(item.access_location._value)

        return aia_uri_list

    def return_cert_aki(self, ssl_certificate):
        """
        Get the Authority Key Identifier (AKI) from a certificate.

        Args:
            ssl_certificate (x509.Certificate): The SSL certificate.

        Returns:
            x509.AuthorityKeyIdentifier: The AKI extension or None if not found.
        """
        try:
            cert_aki = ssl_certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            )
        except x509.extensions.ExtensionNotFound:
            cert_aki = None
        return cert_aki

    def return_cert_ski(self, ssl_certificate):
        """
        Get the Subject Key Identifier (SKI) from a certificate.

        Args:
            ssl_certificate (x509.Certificate): The SSL certificate.

        Returns:
            x509.SubjectKeyIdentifier: The SKI extension.
        """
        cert_ski = ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )

        return cert_ski

    def load_root_ca_cert_chain(
        self,
        filename: str = None,
        ca_cert_text: str = None,
    ) -> Dict[str, str]:
        """
        Load the root CA certificate chain from a file or text.

        Args:
            filename (str, optional): The file name containing the root CA certificates.
            ca_cert_text (str, optional): The text containing the root CA certificates.

        Returns:
            Dict[str, str]: A dictionary containing the root CA certificates.
        """
        if filename is None and ca_cert_text is None:
            raise ValueError("Either filename or ca_cert_text must be provided")

        ca_root_store = {}

        if filename:
            with open(filename, "r") as f_ca_cert:
                ca_cert_text = f_ca_cert.read()

        lines = ca_cert_text.splitlines()
        line_count = len(lines)
        index = 0

        while index < line_count:
            current_line = lines[index]

            if re.search(r"^-----BEGIN CERTIFICATE-----", current_line):
                root_ca_cert = ""
                index += 1
                while index < line_count and not re.search(
                    r"^-----END CERTIFICATE-----", lines[index]
                ):
                    root_ca_cert += lines[index] + "\n"
                    index += 1

                root_ca_cert += lines[index] + "\n"
                index += 1

                cert = x509.load_pem_x509_certificate(
                    root_ca_cert.encode(), default_backend()
                )
                root_ca_name = cert.subject.rfc4514_string()

                ca_root_store[root_ca_name] = root_ca_cert
            else:
                index += 1

        print(f"Number of Root CA's loaded: {len(ca_root_store)}")
        return ca_root_store

    def walk_the_chain(
        self,
        ssl_certificate: x509.Certificate,
        depth: int,
        max_depth: int = 4,
    ):
        if depth <= max_depth:
            cert_aki = self.return_cert_aki(ssl_certificate)
            cert_ski = self.return_cert_ski(ssl_certificate)

            cert_aki_value = (
                cert_aki._value.key_identifier if cert_aki is not None else None
            )
            cert_ski_value = cert_ski._value.digest
            logging.info(
                f"Depth: {depth} - AKI: {cert_aki_value} - SKI: {cert_ski_value}"
            )

            if cert_aki_value is not None:
                aia_uri_list = self.return_cert_aia_list(ssl_certificate)
                if aia_uri_list:
                    for item in aia_uri_list:
                        next_cert = self.get_certificate_from_uri(item)

                        if next_cert is not None:
                            self.cert_chain.append(next_cert)
                            self.walk_the_chain(next_cert, depth + 1, max_depth)
                        else:
                            logging.warning("Could not retrieve certificate.")
                            sys.exit(1)
                else:
                    logging.warning("Certificate didn't have AIA.")
                    ca_root_store = self.load_root_ca_cert_chain("cacert.pem")
                    root_ca_cn = None

                    for root_ca in ca_root_store:
                        try:
                            root_ca_certificate_pem = ca_root_store[root_ca]
                            root_ca_certificate = x509.load_pem_x509_certificate(
                                root_ca_certificate_pem.encode("ascii")
                            )
                            root_ca_ski = self.return_cert_ski(root_ca_certificate)
                            root_ca_ski_value = root_ca_ski._value.digest

                            if root_ca_ski_value == cert_aki_value:
                                root_ca_cn = root_ca
                                self.cert_chain.append(root_ca_certificate)
                                logging.info(
                                    f"Root CA Found - {root_ca_cn}\nCERT_CHAIN - {self.cert_chain}"
                                )
                                break
                        except x509.extensions.ExtensionNotFound:
                            logging.info("Root CA didn't have a SKI. Skipping...")
                            pass

                    if root_ca_cn is None:
                        logging.error("Root CA NOT found.")
                        sys.exit(1)

    def run(self, args: argparse.Namespace):
        self.domain = args.domain
        self.parsed_domain = self.check_domain()

        if args.remove_ca_files:
            self.remove_ca_files()

        if args.get_ca_cert_pem:
            self.get_ca_cert_pem()

        ssl_certificate = self.get_certificate(
            self.parsed_domain["hostname"], self.parsed_domain["port"]
        )

        aia = self.return_cert_aia(ssl_certificate)

        if aia is not None and not self.return_cert_aia(ssl_certificate):
            logging.error(
                "Could not find AIA, possible decryption taking place upstream?"
            )
            sys.exit(1)

        self.cert_chain.append(ssl_certificate)

        self.walk_the_chain(ssl_certificate, 1, max_depth=4)

        self.write_chain_to_file(self.cert_chain)

        print("Certificate chain downloaded and saved.")


def main() -> None:
    """
    Main function to execute the script. Parses arguments, retrieves the SSL certificate, walks the chain,
    and writes the certificate chain and PEM-encoded certificates.
    """
    args = parse_arguments()
    downloader = SSLCertificateChainDownloader()
    downloader.run(args)


if __name__ == "__main__":
    main()
