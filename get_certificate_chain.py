"""
Download SSL certificate chain and save as PEM files.

This script connects to a given website, downloads its SSL certificate,
and saves it as a PEM file. If the certificate has an Authority Information
Access (AIA) extension, the script will download each certificate in the chain
and save them as PEM files as well.

"""
# Standard library imports
import glob
import json
import os
import logging
import re
import ssl
import socket
import sys
from typing import Any, Dict, List
from urllib.request import urlopen

# Third-party library imports
import argparse
import requests
import xmltodict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from dotenv import load_dotenv
from xml.etree.ElementTree import tostring

# Palo Alto Networks imports
from panos import panorama


VERSION = "0.1.0"
CERT_CHAIN = []

# ----------------------------------------------------------------------------
# Configure logging
# ----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


# ----------------------------------------------------------------------------
# Load environment variables from .env file
# ----------------------------------------------------------------------------
load_dotenv(".env")
PANURL = os.environ.get("PANURL", "panorama.lab.com")
PANTOKEN = os.environ.get("PANTOKEN", "mysecretpassword")


# ----------------------------------------------------------------------------
# Function to parse command line arguments
# ----------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Export security rules and associated Security Profile Groups to a CSV file."
    )
    parser.add_argument(
        "--pan-url",
        dest="pan_url",
        default=PANURL,
        help="Panorama URL (default: %(default)s)",
    )
    parser.add_argument(
        "--pan-token",
        dest="api_token",
        default=PANTOKEN,
        help="Panorama API Token (default: %(default)s)",
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


# ----------------------------------------------------------------------------
# Function to create and return an instance of Panorama
# ----------------------------------------------------------------------------
def setup_panorama_client(pan_url: str, api_token: str) -> panorama.Panorama:
    return panorama.Panorama(hostname=pan_url, api_key=api_token)


# ----------------------------------------------------------------------------
# Function to remove the certificate files in current working directory
# ----------------------------------------------------------------------------
def remove_cacert_pem():
    """
    Remove the certificate files in current working directory (*.crt, *.pem).
    """
    for crt_file in glob.glob("*.crt"):
        os.remove(crt_file)
    for pem_file in glob.glob("*.pem"):
        os.remove(pem_file)


# ----------------------------------------------------------------------------
# Function to get cacert.pem from curl.se website to help find Root CA
# ----------------------------------------------------------------------------
def get_cacert_pem():
    """
    Get cacert.pem from curl.se website to help find Root CA.
    """
    cacert_pem_url = "https://curl.se/ca/cacert.pem"
    cacert_pem_file = "cacert.pem"
    logging.info("Downloading %s to %s", cacert_pem_url, cacert_pem_file)
    with urlopen(cacert_pem_url) as response, open(cacert_pem_file, "wb") as out_file:
        if response.getcode() != 200:
            logging.error(
                "Error downloading %s. HTTP status code: %s",
                cacert_pem_url,
                response.getcode(),
            )
            sys.exit(1)
        data = response.read()  # a `bytes` object
        out_file.write(data)
    logging.info("Downloaded %s to %s", cacert_pem_url, cacert_pem_file)


# ----------------------------------------------------------------------------
# Function to parse --domain argument
# ----------------------------------------------------------------------------
def check_domain(domain: str) -> Dict[str, Any]:
    """Parse --hostname argument."""
    hostname, _, port = domain.partition(":")
    return {"hostname": hostname, "port": int(port) if port else 443}


# ----------------------------------------------------------------------------
# Function to run our command
# ----------------------------------------------------------------------------
def fetch_system_information(pan: panorama.Panorama) -> Dict[str, Any]:
    system_info = pan.op("show system info")
    xml_string = tostring(system_info).decode(
        "utf-8"
    )  # Convert the Element object to a string
    xml_dict = xmltodict.parse(
        xml_string
    )  # Parse the XML string to a Python dictionary
    return json.loads(json.dumps(xml_dict))  # Convert the Python dictionary to JSON


# ----------------------------------------------------------------------------
# Function to get the SSL certificate from the website
# ----------------------------------------------------------------------------
def get_certificate(hostname: str, port: int) -> x509.Certificate:
    """
    Get the SSL certificate from the website.

    Args:
        hostname: The website hostname.
        port: The website port.

    Returns:
        The SSL certificate as an x509.Certificate object.
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


# ----------------------------------------------------------------------------
# Function to normalize the subject name
# ----------------------------------------------------------------------------
def normalize_subject(subject: str) -> str:
    """
    Normalize the subject name by removing spaces and special characters.

    Args:
        subject: The subject name string.

    Returns:
        The normalized subject name string.
    """
    return re.sub(r"\W+", "_", subject)


# ----------------------------------------------------------------------------
# Function to save the SSL certificate as a PEM file
# ----------------------------------------------------------------------------
def save_ssl_certificate(ssl_certificate: x509.Certificate, file_name: str) -> None:
    """
    Save the SSL certificate as a PEM file.

    Args:
        ssl_certificate: The SSL certificate as an x509.Certificate object.
        file_name: The name of the PEM file to save the certificate to.
    """
    with open(file_name, "wb") as f:
        f.write(ssl_certificate.public_bytes(encoding=serialization.Encoding.PEM))


# ----------------------------------------------------------------------------
# Function to write the chain to separate files
# ----------------------------------------------------------------------------
def write_chain_to_file(certificate_chain: List[x509.Certificate]) -> None:
    """
    Write all the elements in the chain to separate files.

    Args:
        certificate_chain: A list of SSL certificates as x509.Certificate objects.
    """
    for counter, certificate_item in enumerate(certificate_chain):
        cert_subject = certificate_item.subject.rfc4514_string()
        normalized_subject = normalize_subject(cert_subject)
        ssl_certificate_filename = (
            f"{len(certificate_chain) - 1 - counter}-{normalized_subject}.crt"
        )
        save_ssl_certificate(certificate_item, ssl_certificate_filename)


# ----------------------------------------------------------------------------
# Function to return the AIA extension of the SSL certificate
# ----------------------------------------------------------------------------
def return_cert_aia(ssl_certificate: x509.Certificate) -> x509.Extensions:
    """
    Returns the AIA extension of the SSL certificate, if available.

    Args:
        ssl_certificate: The SSL certificate as an x509.Certificate object.

    Returns:
        The AIA extension as an x509.Extensions object, or None if not present.
    """
    try:
        aia = ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        return aia
    except x509.ExtensionNotFound:
        return None


# ----------------------------------------------------------------------------
# Function to download the certificate from the given URI
# ----------------------------------------------------------------------------
def get_certificate_from_uri(uri: str) -> x509.Certificate:
    """
    Download the certificate from the given URI and return it as an
    x509.Certificate object.

    Args:
        uri: The URI to download the certificate from.

    Returns:
        The downloaded certificate as an x509.Certificate object, or
        None if there was an error.
    """
    try:
        response = requests.get(uri)

        if response.status_code == 200:
            aia_content = response.content
            ssl_certificate = ssl.DER_cert_to_PEM_cert(aia_content)
            cert = x509.load_pem_x509_certificate(
                ssl_certificate.encode("ascii"), default_backend()
            )
            return cert
        else:
            return None
    except Exception:
        return None


# ----------------------------------------------------------------------------
# Function to return a list of AIA's defined in the SSL certificate
# ----------------------------------------------------------------------------
def return_cert_aia_list(ssl_certificate: x509.Certificate) -> list:
    """
    Returns a list of AIA's defined in the SSL certificate.

    Args:
        ssl_certificate: The SSL certificate as an x509.Certificate object.

    Returns:
        A list of AIA's, or an empty list if none are present.
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


# ----------------------------------------------------------------------------
# Function to return the AKI extension of the SSL certificate
# ----------------------------------------------------------------------------
def return_cert_aki(ssl_certificate):
    """Returns the AKI of the certificate."""
    try:
        cert_aki = ssl_certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
    except x509.extensions.ExtensionNotFound:
        cert_aki = None
    return cert_aki


# ----------------------------------------------------------------------------
# Function to return the SKI extension of the SSL certificate
# ----------------------------------------------------------------------------
def return_cert_ski(ssl_certificate):
    """Returns the SKI of the certificate."""
    cert_ski = ssl_certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )

    return cert_ski


# ----------------------------------------------------------------------------
# Function to return the SAN extension of the SSL certificate
# ----------------------------------------------------------------------------
def load_root_ca_cert_chain(filename: str) -> Dict[str, str]:
    """
    Load the Root CA Chain in a structured format.
    ca_root_store = {
        "Root CA Name 1": "<PEM format1>",
        "Root CA Name 2": "<PEM format2>",
        ...
    }
    """
    ca_root_store = {}
    try:
        with open(filename, "r") as f_ca_cert:
            while True:
                previous_line = f_ca_cert.readline()
                current_line = f_ca_cert.readline()

                if not current_line:
                    break

                if re.search("^\={5,}", current_line):
                    root_ca_cert = ""
                    root_ca_name = previous_line.strip()

                    while True:
                        ca_cert_line = f_ca_cert.readline()
                        if ca_cert_line.strip() != "-----END CERTIFICATE-----":
                            root_ca_cert += ca_cert_line
                        else:
                            root_ca_cert += "-----END CERTIFICATE-----\n"
                            break

                    ca_root_store[root_ca_name] = root_ca_cert

        print(f"Number of Root CA's loaded: {len(ca_root_store)}")
        return ca_root_store

    except FileNotFoundError:
        print(
            "Could not find cacert.pem file. Please run script with --get-ca-cert-pem to get the file from curl.se website."
        )
        sys.exit(1)


# ----------------------------------------------------------------------------
# Function to return the AKI extension of the SSL certificate
# ----------------------------------------------------------------------------
def walk_the_chain(ssl_certificate: x509.Certificate, depth: int, max_depth: int = 4):
    """
    Both functions walk through the certificate chain by fetching information
    from the Authority Information Access (AIA) extension until the Authority
    Key Identifier (AKI) equals the Subject Key Identifier (SKI), indicating
    that the Root CA has been found.

    If a certificate does not have the AIA extension, the functions try to
    find the root certificate from a standard root store. The functionality
    remains the same in both versions.
    """

    if depth <= max_depth:
        # Retrieve the AKI and SKI from the certificate
        cert_aki = return_cert_aki(ssl_certificate)
        cert_ski = return_cert_ski(ssl_certificate)

        cert_aki_value = (
            cert_aki._value.key_identifier if cert_aki is not None else None
        )
        cert_ski_value = cert_ski._value.digest
        print(f"cert_ski_value: {cert_ski_value}")

        if cert_aki_value is not None:
            aia_uri_list = return_cert_aia_list(ssl_certificate)
            if aia_uri_list:
                for item in aia_uri_list:
                    next_cert = get_certificate_from_uri(item)

                    if next_cert is not None:
                        CERT_CHAIN.append(next_cert)
                        walk_the_chain(next_cert, depth + 1, max_depth)
                    else:
                        print("Could not retrieve certificate.")
                        sys.exit(1)
            else:
                # Certificate didn't have AIA, find the root from a standard root store
                print("Certificate didn't have AIA...ruh roh.")
                ca_root_store = load_root_ca_cert_chain("cacert.pem")
                root_ca_cn = None

                for root_ca in ca_root_store:
                    try:
                        root_ca_certificate_pem = ca_root_store[root_ca]
                        root_ca_certificate = x509.load_pem_x509_certificate(
                            root_ca_certificate_pem.encode("ascii")
                        )
                        root_ca_ski = return_cert_ski(root_ca_certificate)
                        root_ca_ski_value = root_ca_ski._value.digest

                        if root_ca_ski_value == cert_aki_value:
                            root_ca_cn = root_ca
                            print(f"Root CA Found - {root_ca_cn}")
                            CERT_CHAIN.append(root_ca_certificate)
                            break
                    except x509.extensions.ExtensionNotFound:
                        # Apparently some Root CA's don't have a SKI?
                        pass

                if root_ca_cn is None:
                    print("ERROR - Root CA NOT found.")
                    sys.exit(1)


# ----------------------------------------------------------------------------
# Main execution of the script
# ----------------------------------------------------------------------------
def main() -> None:
    args = parse_arguments()

    if args.remove_ca_files:
        # Remove the .pem and .crt files from the current directory.
        try:
            remove_cacert_pem()
        except FileNotFoundError:
            pass

    if args.get_ca_cert_pem:
        # Download the cacert.pem file from the Internet.
        get_cacert_pem()

    domain = check_domain(args.domain)

    # Get the SSL certificate from the website.
    ssl_certificate = get_certificate(domain["hostname"], domain["port"])

    # Get the AIA extension from the certificate
    aia = return_cert_aia(ssl_certificate)

    # Check if the AIA extension is present

    if aia is not None and not return_cert_aia(ssl_certificate):
        print(
            "ERROR - I could not find AIA. Possible decryption taking place upstream?"
        )
        sys.exit(1)

    # Append the ssl_certificate object to the CERT_CHAIN list.
    CERT_CHAIN.append(ssl_certificate)

    # Walk the chain up until we get the Root CA.
    walk_the_chain(ssl_certificate, 1, max_depth=4)

    # Write the certificate chain to individual files.
    write_chain_to_file(CERT_CHAIN)

    print("Certificate chain downloaded and saved.")


# ----------------------------------------------------------------------------
# Execute the main function
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
