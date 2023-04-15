# Get Certificate Chain 🌐🔐

This Python script retrieves the certificate chain from a website, allowing you to analyze and verify the SSL/TLS certificates of the website. The original source can be found [here](https://github.com/TheScriptGuy/getCertificateChain), and the overwhelming majority of credit goes to [TheScriptGuy](https://github.com/TheScriptGuy).

This repository is a fork of that project to act as a customized plugin for the [PAN Dashboard](https://github.com/cdot65/pan-dashboard/) project, allowing users to retrieve the certificate chain of a website from within the PAN Dashboard and have it uploaded to a PAN-OS or Panorama appliance.

## Table of Contents

- [Get Certificate Chain 🌐🔐](#get-certificate-chain-)
  - [Table of Contents](#table-of-contents)
  - [Requirements 📋](#requirements-)
  - [Creating Virtual Environment with Poetry 🌱](#creating-virtual-environment-with-poetry-)
  - [Creating Virtual Environment without Poetry 🌱](#creating-virtual-environment-without-poetry-)
  - [Usage 🚀](#usage-)
    - [Arguments](#arguments)
  - [Examples](#examples)
  - [License](#license)

## Requirements 📋

- Python 3.10+
- Poetry (optional) - [Python Poetry](https://python-poetry.org/docs/)

## Creating Virtual Environment with Poetry 🌱

To create a virtual environment with Poetry, follow these steps:

1. Install Poetry if you haven't already:

    ```bash
    curl -sSL https://install.python-poetry.org | python3 -
    ```

2. Create a virtual environment:

    ```bash
    poetry install
    ```

3. Activate the virtual environment:

    ```bash
    poetry shell
    ```

## Creating Virtual Environment without Poetry 🌱

To create a virtual environment without Poetry, follow these steps:

1. Create a virtual environment:

    ```bash
    python3 -m venv venv
    ```

2. Activate the virtual environment:

    ```bash
    source venv/bin/activate
    ```

3. Install the required packages:

    ```bash
    pip install cryptography argparse requests
    ```

## Usage 🚀

To use the script, run the following command:

```bash
python getCertChain.py --hostname www.google.com
```

### Arguments

- `--hostname`: The hostname:port pair that the script should connect to. Defaults to www.google.com:443.
- `--removeCertificateFiles`: Remove the certificate files in the current working directory (*.crt, *.pem).
- `--getCAcertPEM`: Get cacert.pem from the curl.se website to help find Root CA.

## Examples

Get the certificate chain for www.example.com:

```bash
python getCertChain.py --hostname www.example.com
```

Get the certificate chain for www.example.com:8443:

```bash
python getCertChain.py --hostname www.example.com:8443
```

Get the certificate chain for www.example.com:8443 and remove the certificate files in the current working directory (*.crt, *.pem):

```bash
python getCertChain.py --hostname www.example.com:8443 --removeCertificateFiles
```

Get the certificate chain for www.example.com:8443 and get cacert.pem from the curl.se website to help find Root CA:

```bash
python getCertChain.py --hostname www.example.com:8443 --getCAcertPEM
```

Get the certificate chain for www.example.com:8443, remove the certificate files in the current working directory (*.crt, *.pem), and get cacert.pem from the curl.se website to help find Root CA:

```bash
python getCertChain.py --hostname www.example.com:8443 --removeCertificateFiles --getCAcertPEM
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
