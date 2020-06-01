# Ansible Collection - phoenixnap.ansible_pnap

Collection of modules for phoenixNAP Bare Metal Cloud API

## Requirements

### Python Modules

* requests

To install module execute:

> pip install requests

## Installation

> ansible-galaxy collection install phoenixnap.bmc

## Documentation

After installation, see module documentation: 

> ansible-doc phoenixnap.bmc.server

## Authentication (Credential File)

In your home directory create folder `.pnap` and within the file `config.yaml` containing the following information:

    clientId: myClientId
    clientSecret: myClientSecret