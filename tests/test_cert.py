import pytest
import os
from getCertChain import (
    normalizeSubject,
    returnCertSKI,
    returnCertAIAList,
    checkHostname,
)
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import serialization


def test_normalizeSubject():
    subject = (
        "CN=www.example1.com, O=Example Company, L=San Francisco, ST=California, C=US"
    )
    normalized = normalizeSubject(subject)
    assert normalized == "www.example1.com"


def test_returnCertSKI(sslCertificate):
    certSKI = returnCertSKI(sslCertificate)
    assert certSKI.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER


def test_returnCertAIAList(sslCertificate):
    aiaList = returnCertAIAList(sslCertificate)
    assert isinstance(aiaList, list)


def test_checkHostname():
    hostname = "www.example1.com:8443"
    parsed = checkHostname(hostname)
    assert parsed == {"hostname": "www.example1.com", "port": 8443}

    hostname = "www.example1.com"
    parsed = checkHostname(hostname)
    assert parsed == {"hostname": "www.example1.com", "port": 443}


@pytest.fixture
def sslCertificate():
    test_pem_file = os.path.join(os.path.dirname(__file__), "example1_cert.pem")
    with open(test_pem_file, "rb") as f:
        pem_data = f.read()

    cert = x509.load_pem_x509_certificate(pem_data)
    return cert
