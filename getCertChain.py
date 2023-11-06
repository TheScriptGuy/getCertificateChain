# Description:     Get the certificate chain from a website.
# Author:          TheScriptGuy
# Last modified:   2023-11-04
# Version:         0.07

import argparse
import sys
import os

from ConnectionManager import ConnectionManager
from FileManager import FileManager
from CertificateManager import CertificateManager

scriptVersion = "0.07"
maxDepth = 4
certChain = []


def parseArguments():
    """Create argument options and parse through them to determine what to do with script."""
    # Instantiate the parser
    parser = argparse.ArgumentParser(description=f'Get Certificate Chain v{scriptVersion}')

    # Optional arguments
    parser.add_argument('--hostname', default='www.google.com:443',
                        help='The hostname:port pair that the script should connect to. Defaults to www.google.com:443.')

    parser.add_argument('--removeCertificateFiles', action='store_true',
                        help='Remove the certificate files in current working directory (*.crt, *.pem).')

    parser.add_argument('--getCAcertPEM', action='store_true',
                        help='Get cacert.pem from curl.se website to help find Root CA.')

    parser.add_argument('--insecure', action='store_true',
                        help='Allow insecure connections to establish.')

    global args

    args = parser.parse_args()


def getCAcertPEM() -> None:
    """Retrieves the cacert.pem file from curl.se website."""
    connection_manager = ConnectionManager()
    file_manager = FileManager()

    file_manager.write_to_file(
        connection_manager.get_file_contents("https://curl.se/ca/cacert.pem"),
        "cacert.pem"
        )


def main():
    """Main subroutine."""
    # Parse the arguments
    parseArguments()

    # If --removeCertificateFiles is passed, remove files and exit
    if args.removeCertificateFiles:
        file_manager = FileManager()
        file_manager.delete_files(["*.crt", "*.pem"])
        sys.exit(0)

    if args.getCAcertPEM:
        getCAcertPEM()


    # Check to see if hostname argument is passed. If not, exit.
    if args.hostname:
        # Define a connection_manager object as ConnectionManager class
        connection_manager = ConnectionManager()
        connection_manager.configure_hostname(args.hostname)
    else:
        # No hostname argument was supplied. Exit.
        print("Please supply a --hostname argument.")
        sys.exit(1)

    
    # Define a certificate_manager object from CertificateManager class
    certificate_manager = CertificateManager("cacert.pem", maxDepth)

    # Get the website certificate object, by default it's a secure connection.
    if args.insecure:
        certificate = connection_manager.get_certificate(secure=False)
    else:
        certificate = connection_manager.get_certificate()

    certificate_manager.set_certificate(certificate)
    
    # Prepare to walk the chain
    certificate_manager.start_walk_of_chain()

    # Now lets write the contents to a file
    certificate_manager.write_chain_to_file()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        print()
        try:
            sys.exit(0)
        except SystemExit:
            os.exit(0)
