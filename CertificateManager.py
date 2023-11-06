import ssl
import re
import sys
from cryptography import x509
#from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, serialization
from typing import Dict, Optional

from FileManager import FileManager
from ConnectionManager import ConnectionManager

class CertificateManager:
    version = '1.0'

    def __init__(self, file_path: str, max_chain_depth: int):
        self.cacerts = self.load_cacerts(file_path)
        self.max_chain_depth = max_chain_depth
        self.cert_chain = []


    @staticmethod
    def _extract_common_name(cert_obj: x509.Certificate) -> str:
        """Extracts the common name from the certificate object."""
        # Note: Update or implement as needed based on actual method to extract CN.
        try:
            common_names = cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if common_names:
                return common_names[0].value
        except x509.ExtensionNotFound:
            pass
        return ""

    @staticmethod
    def _extract_ski(cert_obj: x509.Certificate) -> str:
        """Extracts the SKI from the certificate object."""
        try:
            ski_extension = cert_obj.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            return ski_extension.value.digest.hex()
        except x509.ExtensionNotFound:
            return ""

    def load_cacerts(self, __filename: str) -> dict:
        """
        Load the Root CA Chain in a structured format.
        caRootStore = {
            "Root CA Name 1": {
              "pem": "<PEM format1>",
              "SKI": "Subject Key Identifier"
            },
            "Root CA Name 2": {
              "pem": "<PEM format1>",
              "SKI": "Subject Key Identifier"    
            }",
            ...
        }
        """
        previousLine = ""
        currentLine = ""

        caRootStore = {}
        try:
            with open(__filename, "r") as f_caCert:
                while True:
                    previousLine = currentLine
                    currentLine = f_caCert.readline()

                    if not currentLine:
                        break

                    if re.search("^\={5,}", currentLine):
                        # This is where the Root CA certificate file begins.
                        # Iterate through all the lines between
                        # -----BEGIN CERTIFICATE-----
                        # ...
                        # -----END CERTIFICATE-----
                        rootCACert = ""
                        rootCAName = previousLine.strip()

                        while True:
                            caCertLine = f_caCert.readline()
                            if caCertLine.strip() != "-----END CERTIFICATE-----":
                                rootCACert += caCertLine
                            else:
                                rootCACert += "-----END CERTIFICATE-----\n"
                                break

                        caRootStore[rootCAName] = {}
                        caRootStore[rootCAName]["pem"] = rootCACert
                        caRootStore[rootCAName]["SKI"] = self._extract_ski(
                            x509.load_pem_x509_certificate(rootCACert.encode())
                            )

            print(f"Number of Root CA's loaded: {len(caRootStore)}")

            return caRootStore

        except FileNotFoundError:
            print("Could not find cacert.pem file. Please run script with --getCAcertPEM to get the file from curl.se website.")
            sys.exit(1)


    def print_cacerts(self) -> None:
        """Print the loaded CA certificates with truncated PEM content."""
        for subject, cert_info in self.cacerts_dict.items():
            pem_content = cert_info['pem_certificate'].split("-----BEGIN CERTIFICATE-----")[1].strip()
            print(f"Subject: {subject: <60}SKI: {cert_info['SKI']} PEM_Cert: {pem_content[:15]}...")


    def query_cacerts(self, ski: str) -> Optional[Dict[str, str]]:
        """
        Query the loaded CA certificates with an SKI and return the certificate details.

        Parameters:
            ski (str): The Subject Key Identifier to query.

        Returns:
            Optional[Dict[str, str]]: The details of the certificate if found, otherwise None.
        """
        return next((cert_info for cert_info in self.cacerts_dict.values() if cert_info['SKI'] == ski), None)


    def set_certificate(self, __certificate: x509.Certificate) -> None:
        """Puts the certificate object into this class for processing."""
        self.certificate = __certificate


    @staticmethod
    def returnCertAKI(__sslCertificate: x509.Certificate) -> Optional[x509.extensions.Extension]:
        """Returns the AKI of the certificate."""
        try:
            certAKI = __sslCertificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        except x509.extensions.ExtensionNotFound:
            certAKI = None
        return certAKI


    @staticmethod
    def returnCertSKI(__sslCertificate: x509.Certificate) -> x509.extensions.Extension:
        """Returns the SKI of the certificate."""
        certSKI = __sslCertificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)

        return certSKI


    @staticmethod    
    def returnCertAIA(__sslCertificate: x509.Certificate) -> Optional[x509.extensions.Extension]:
        """Returns the AIA of the certificate. If not defined, then return None."""
        try:
            certAIA = __sslCertificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)

        except x509.extensions.ExtensionNotFound:
            certAIA = None

        return certAIA


    @staticmethod
    def returnCertAIAList(__sslCertificate: x509.Certificate) -> list:
        """Returns a list of AIA's defined in __sslCertificate."""
        aiaUriList = []

        # Iterate through all the extensions.
        for extension in __sslCertificate.extensions:
            certValue = extension.value

            # If the extension is x509.AuthorityInformationAccess) then lets get the caIssuers from the field.
            if isinstance(certValue, x509.AuthorityInformationAccess):
                dataAIA = list(certValue)
                for item in dataAIA:
                    if item.access_method._name == "caIssuers":
                        aiaUriList.append(item.access_location._value)

        # Return the aiaUriList back to the script.
        return aiaUriList


    def start_walk_of_chain(self):
        if self.certificate is not None:
            # Get the AIA from the __websiteCertificate object
            aia = self.returnCertAIA(self.certificate)

            if aia is not None:
                # Append the self.certificate object to the self.cert_chain list.
                self.cert_chain.append(self.certificate)

                # Now we walk the chain up until we get the Root CA.
                self.walk_the_chain(self.certificate, 1)

            else:
                print("ERROR - I could not find AIA. Possible decryption taking place upstream?")
                sys.exit(1)
        else:
            # self.certificate has not been defined yet.
            sys.exit(1)


    def walk_the_chain(self, __sslCertificate: x509.Certificate, __depth: int) -> None:
        """
        Walk the length of the chain, fetching information from AIA
        along the way until AKI == SKI (i.e. we've found the Root CA.

        This is to prevent recursive loops. Usually there are only 4 certificates.
        If the self.max_chain_depth is too small (why?) adjust it at the beginning of the script.
        """
        if __depth <= self.max_chain_depth:
            # Retrive the AKI from the certificate.
            certAKI = self.returnCertAKI(__sslCertificate)
            # Retrieve the SKI from the certificate.
            certSKI = self.returnCertSKI(__sslCertificate)

            # Sometimes the AKI can be none. Lets handle this accordingly.
            if certAKI is not None:
                certAKIValue = certAKI._value.key_identifier
            else:
                certAKIValue = None

            # Sometimes the AKI can be none. Lets handle this accordingly.
            if certAKIValue is not None:
                aiaUriList = self.returnCertAIAList(__sslCertificate)
                if aiaUriList:
                    # Iterate through the aiaUriList list.
                    for item in aiaUriList:
                        # Define a connection_manager object.
                        connection_manager = ConnectionManager()
                        # get the certificate for the item element.
                        nextCert = connection_manager.get_certificate_from_uri(item)

                        # If the certificate is not none (great), append it to the self.cert_chain, increase the __depth and run the walk_the_chain subroutine again.
                        if nextCert is not None:
                            self.cert_chain.append(nextCert)
                            __depth += 1
                            self.walk_the_chain(nextCert, __depth)
                        else:
                            print("Could not retrieve certificate.")
                            sys.exit(1)
                else:
                    """Now we have to go on a hunt to find the root from a standard root store."""
                    print("Certificate didn't have AIA...ruh roh.")

                    # Assume we cannot find a Root CA
                    rootCACN = None

                    # Iterate through the self.cacerts object.
                    for rootCA in self.cacerts:
                        try:
                            if self.cacerts[rootCA]['SKI'] == certAKIValue.hex():
                                rootCACN = rootCA
                                print(f"Root CA Found - {rootCA}")
                                cert_obj = x509.load_pem_x509_certificate(self.cacerts[rootCA]['pem'].encode('utf-8'))
                                self.cert_chain.append(cert_obj)
                                break
                        except x509.extensions.ExtensionNotFound:
                            # Apparently some Root CA's don't have a SKI?
                            pass

                    if rootCACN is None:
                        print("ERROR - Root CA NOT found.")
                        sys.exit(1)


    @staticmethod
    def _normalize_subject(subject: str) -> str:
        """Normalize the subject name to use for file name purposes."""
        normalizedName = subject.split(',')
        # Initialize commonName with None to check later if it was set
        commonName = None
        # Iterate through all the elements of normalizedName, finding the CN= one.
        for item in normalizedName:
            prefix = item[:3]
            if prefix in ("CN=", "OU="):
                itemIndex = item.find('=')
                commonName = item[itemIndex+1:]
                break
            elif not commonName:  # This will catch the first item if no CN= or OU= is found
                itemIndex = item.find('=')
                commonName = item[itemIndex+1:]

        # Replace spaces with hyphens
        commonName = commonName.replace(' ', '-')

        # Remove wildcards
        commonName = commonName.replace('*.', '')

        # Make sure the filename string is lower case
        new_normalized_name = ''.join(commonName).lower()

        # Ensure we return a string even if commonName remains None
        return new_normalized_name if new_normalized_name is not None else ""


    def write_chain_to_file(self) -> None:
        """Write all the elements in the chain to file."""
        # Iterate through all the elements in the chain.

        file_manager = FileManager()

        cert_chain_length = len(self.cert_chain)

        for counter, certificateItem in enumerate(self.cert_chain):
            # Get the subject from the certificate.
            certSubject = certificateItem.subject.rfc4514_string()

            # Normalize the subject name
            normalized_subject = self._normalize_subject(certSubject)

            # Generate the certificate file name
            sslCertificateFilename = str(cert_chain_length - 1 - counter) + '-' + normalized_subject + '.crt'

            # Send the certificate object to the sslCertificateFileName filename
            file_manager.write_to_file(
                certificateItem.public_bytes(
                    encoding=serialization.Encoding.PEM
                    ), 
                sslCertificateFilename
                )  
