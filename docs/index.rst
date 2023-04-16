.. _get_certificate_chain:

Get Certificate Chain 🌐🔐
==========================

This Python script retrieves the certificate chain from a website, allowing you to analyze and verify the SSL/TLS certificates of the website. The original source can be found `here <https://github.com/TheScriptGuy/getCertificateChain>`_, and the overwhelming majority of credit goes to `TheScriptGuy <https://github.com/TheScriptGuy>`_.

This repository will operate as a custom fork of that project to act as a customized plugin for the `PAN Dashboard <https://github.com/cdot65/pan-dashboard/>`_ project, allowing users to retrieve the certificate chain of a website from within the PAN Dashboard and have it uploaded to a PAN-OS or Panorama appliance.


Requirements 📋
===============

- Python 3.10+
- Poetry (optional) - `Python Poetry <https://python-poetry.org/docs/>`_


Creating Virtual Environment with Poetry 🌱
============================================

To create a virtual environment with Poetry, follow these steps:

1. Install Poetry if you haven't already:

   .. code-block:: bash

      curl -sSL https://install.python-poetry.org | python3 -

2. Create a virtual environment:

   .. code-block:: bash

      poetry install

3. Activate the virtual environment:

   .. code-block:: bash

      poetry shell


Creating Virtual Environment without Poetry 🌱
===============================================

To create a virtual environment without Poetry, follow these steps:

1. Create a virtual environment:

   .. code-block:: bash

      python3 -m venv venv

2. Activate the virtual environment:

   .. code-block:: bash

      source venv/bin/activate

3. Install the required packages:

   .. code-block:: bash

      pip install cryptography argparse pytest


Usage 🚀
=========

To use the script, run the following command:

.. code-block:: bash

   python get_certificate_chain.py --domain www.google.com

Arguments
---------

- ``--domain``: The domain:port pair that the script should connect to. Defaults to www.google.com:443.
- ``--rm-ca-files``: Remove the certificate files in the current working directory (``*.crt``, ``*.pem``).
- ``--get-ca-cert-pem``: Get cacert.pem from the curl.se website to help find Root CA.


Examples
========

Get the certificate chain for www.example.com:

.. code-block:: bash

   python get_certificate_chain.py --domain www.example.com

Get the certificate chain for www.example.com:8443:

.. code-block:: bash

   python get_certificate_chain.py --domain www.example.com:8443

Get the certificate chain for www.example.com:8443 and remove the certificate files in the current working directory (``*.crt``, ``*.pem``):

.. code-block:: bash

   python get_certificate_chain.py --domain www.example.com:8443 --rm-ca-files

Get the certificate chain for www.example.com:8443 and get cacert.pem from the curl.se website to help find Root CA:

.. code-block:: bash

   python get_certificate_chain.py
