# Ansible Collection - phoenixnap.ansible_pnap

Ansible Modules to support the phoenixNAP Bare Metal Cloud (BMC)

## Requirements

### Python Modules

* requests

To install module execute:

> pip install requests

## Authentication (Credential File)

In your home directory create folder `.pnap` and within the file `config.yaml` containing the following information:

    clientId: myClientId
    clientSecret: myClientSecret