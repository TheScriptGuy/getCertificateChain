import ssl
import socket
import requests
import sys

from cryptography import x509
from typing import Optional


class ConnectionManager:
    """ConnectionManager Class"""

    version = "0.1"

    def __init__(self) -> None:
        """Initialize the ConnectionManager class."""
        self.starting_hostname = ""

    def configure_hostname(self, __hostname) -> None:
        """Configure the hostname."""
        self.starting_hostname = self.reformat_hostname(__hostname)

    @staticmethod
    def reformat_hostname(__hostname) -> dict:
        """
        Parse __hostname argument.
        Make sure that if a port isn't supplied, then assume default port of 443.
        Return the hostname:port combination as a dict type.
        """
        tmpLine = ""
        hostnameQuery = ""

        # If the ':' is in the hostname argument, then we'll assume it's meant to be a port following the ':'.
        if ":" in __hostname:
            tmpLine = __hostname.split(':')
            hostnameQuery = {"hostname": tmpLine[0], "port": int(tmpLine[1])}
        else:
            # If no ':' is found, then set default port 443.
            hostnameQuery = {"hostname": __hostname, "port": 443}

        return hostnameQuery

    def get_certificate(self, secure: bool = True) -> x509.Certificate:
        """Retrieves the certificate from a hostname:port pair."""
        sslCertificate = None
        try:
            # Create the SSL context
            if secure:
                sslContext = ssl.create_default_context()
            else:
                sslContext = ssl._create_unverified_context()

            with socket.create_connection((self.starting_hostname['hostname'], self.starting_hostname['port'])) as sock:
                with sslContext.wrap_socket(sock, server_hostname=self.starting_hostname['hostname']) as sslSocket:
                    # Get the certificate from the connection, convert it to PEM format.
                    sslCertificate = ssl.DER_cert_to_PEM_cert(sslSocket.getpeercert(True))

            # Load the PEM formatted file.
            sslCertificate = x509.load_pem_x509_certificate(sslCertificate.encode('ascii'))

        except ssl.SSLCertVerificationError as e:
            print(f"SSL Verification error. {e.verify_message}\nTry with the --insecure option.")
            sys.exit(1)
        except ConnectionRefusedError:
            print(f"Connection refused to {self.starting_hostname['hostname']}:{__port}")
            sys.exit(1)

        # Return the sslCertificate object.
        return sslCertificate

    @staticmethod
    def get_file_contents(uri: str) -> Optional[bytes]:
        """
        Retrieve the file contents from a specified URI if the HTTP response code is 200.

        Parameters:
            uri (str): The Uniform Resource Identifier (URI) from which to retrieve the file contents.

        Returns:
            Optional[bytes]: The file contents as bytes if retrieval is successful; None otherwise.

        Raises:
            ValueError: If the URI is empty or None.
            HTTPError: If the HTTP response code is not 200.
            RequestException: If there's an issue with the network request.
        """
        if not uri:
            raise ValueError("The URI must not be empty.")

        try:
            response = requests.get(uri)
            if response.status_code != 200:
                # If the status is not 200, you can raise an HTTPError
                response.raise_for_status()
        except HTTPError as e:
            # Handle specific HTTP errors if needed
            print(f"Received non-200 HTTP status code: {e}")
            sys.exit(1)
        except RequestException as e:
            # Handle any other requests-related exceptions
            print(f"An error occurred while trying to retrieve the file: {e}")
            sys.exit(1)

        return response.content

    def get_certificate_from_uri(self, __uri: str) -> x509.Certificate:
        """Gets the certificate from a URI.
        By default, we're expecting to find nothing. Therefore certI = None.
        If we find something, we'll update certI accordingly.
        """
        certI = None

        # Attempt to get the aia from __uri
        aiaRequest = requests.get(__uri)

        # If response status code is 200
        if aiaRequest.status_code == 200:
            # Get the content and assign to aiaContent
            aiaContent = aiaRequest.content

            # Convert the certificate into PEM format.
            sslCertificate = ssl.DER_cert_to_PEM_cert(aiaContent)

            # Load the PEM formatted content using x509 module.
            certI = x509.load_pem_x509_certificate(sslCertificate.encode('ascii'))

        # Return certI back to the script.
        return certI
