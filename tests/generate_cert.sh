#!/bin/bash

# Create a self-signed certificate with the SKI extension
openssl req -x509 -new -nodes -days 365 -config example.cnf -out example1_cert.pem -extensions v3_ca
