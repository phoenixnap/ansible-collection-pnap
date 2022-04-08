<h1 align="center">
  <br>
  <a href="https://phoenixnap.com/bare-metal-cloud"><img src="https://user-images.githubusercontent.com/78744488/109779287-16da8600-7c06-11eb-81a1-97bf44983d33.png" alt="phoenixnap Bare Metal Cloud" width="300"></a>
  <br>
  Bare Metal Cloud Ansible Collection
  <br>
</h1>

<p align="center">
Ansible collection of modules for interacting with the <a href="https://developers.phoenixnap.com/apis">Bare Metal Cloud API</a>. This collection contains the <i><b>server</b></i> module which allows you to automate <a href="https://phoenixnap.com/bare-metal-cloud">Bare Metal Cloud</a> server provisioning and management.
</p>

<p align="center">
  <a href="https://phoenixnap.com/bare-metal-cloud">Bare Metal Cloud</a> •
  <a href="https://galaxy.ansible.com/phoenixnap/bmc">Ansible Galaxy</a> •
  <a href="https://developers.phoenixnap.com/">Developers Portal</a> •
  <a href="http://phoenixnap.com/kb">Knowledge Base</a> •
  <a href="https://developers.phoenixnap.com/support">Support</a>
</p>

## Requirements

- [Bare Metal Cloud](https://bmc.phoenixnap.com) account
- Ansible 2.9+
- Python 2 (version 2.7) or Python 3 (versions 3.5 and higher)
  - Python **_requests_** package

## Creating a Bare Metal Cloud account

1. Go to the [Bare Metal Cloud signup page](https://support.phoenixnap.com/wap-jpost3/bmcSignup).
2. Follow the prompts to set up your account.
3. Use your credentials to [log in to Bare Metal Cloud portal](https://bmc.phoenixnap.com).

:arrow_forward: **Video tutorial:** [How to Create a Bare Metal Cloud Account in Minutes](https://www.youtube.com/watch?v=hPR60XWOSsQ)
<br>

:arrow_forward: **Video tutorial:** [How to Deploy a Bare Metal Server in a Minute](https://www.youtube.com/watch?v=BzBBwLxR80o)

## Installing Ansible

Follow these helpful tutorials to learn how to install Ansible on Ubuntu and Windows machines.

- [How to Install and Configure Ansible on Ubuntu 20.04](https://phoenixnap.com/kb/install-ansible-ubuntu-20-04)
- [How to Install and Configure Ansible on Windows](https://phoenixnap.com/kb/install-ansible-on-windows)

## Installing the Bare Metal Cloud Ansible module

This Ansible collection contains the **_server_** module which requires the Python **_requests_** HTTP library to work properly. If you don't have it installed on your machine already, run this command to install it:

    pip install requests

Now install the Ansible collection by running:

    ansible-galaxy collection install phoenixnap.bmc

You can view the **_server_** module documentation with this command:

    ansible-doc phoenixnap.bmc.server

## Authentication

You need to create a configuration file called `config.yaml` and save it in the user home directory. This file is used to authenticate access to your Bare Metal Cloud resources.

In your home directory, create a folder `.pnap` and a `config.yaml` file inside it.

This file needs to contain only two lines of code:

    clientId: <enter your client id>
    clientSecret: <enter your client secret>

To get the values for the clientId and clientSecret, follow these steps:

1. [Log in to the Bare Metal Cloud portal](https://bmc.phoenixnap.com).
2. On the left side menu, click on API Credentials.
3. Click the Create Credentials button.
4. Fill in the Name and Description fields, select the permissions scope and click Create.
5. In the table, click on Actions and select View Credentials from the dropdown.
6. Copy the values from the Client ID and Client Secret fields into your `config.yaml` file.

## Example Ansible Playbooks for Bare Metal Cloud

Ansible Playbooks allow you to interact with your Bare Metal Cloud resources. You can create and delete servers as well as perform power actions with simple code instructions.

This example shows you how to deploy a Bare Metal Cloud server and delete it with Ansible Playbooks.

First, create a YAML file `playbook_name.yml`. The _name_ part of the filename should contain the action you want to perform. To create a server, the filename can be `playbook_create.yml`.

Once you've created the file, open it and paste this code:

```yaml

- name: Create new servers for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [my-server-red]
      location: PHX
      os: ubuntu/bionic
      type: s1.c1.medium
      state: present
      ssh_key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"

```
To delete that same server, create a file called `playbook_deprovision.yml` and paste this code:

```yaml

- name: reset servers
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - server:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      hostnames: [my-server-red]
      state: absent

```
Pay attention to the *state* item. This is where you tell Ansible which action you would like to perform. Here's a list of available options:

-   **present**: creates the server
-   **absent**: deletes the server
-   **power-off**: turns off the power supply to the machine
-   **power-on**: turns on the power supply to the machine
-   **rebooted**: restarts the server
-   **reset**: formats the server
-   **shutdown**: works on the operating system

For more examples, check out this helpful tutorial: [Bare Metal Cloud Playbook Examples](https://phoenixnap.com/kb/how-to-install-phoenixnap-bmc-ansible-module#htoc-bmc-playbook-examples)

## Bare Metal Cloud community

Become part of the Bare Metal Cloud community to get updates on new features, help us improve the platform, and engage with developers and other users.

- Follow [@phoenixNAP on Twitter](https://twitter.com/phoenixnap)
- Join the [official Slack channel](https://phoenixnap.slack.com)
- Sign up for our [Developers Monthly newsletter](https://phoenixnap.com/developers-monthly-newsletter)

### Resources

- [Product page](https://phoenixnap.com/bare-metal-cloud)
- [Instance pricing](https://phoenixnap.com/bare-metal-cloud/instances)
- [YouTube tutorials](https://www.youtube.com/watch?v=8TLsqgLDMN4&list=PLWcrQnFWd54WwkHM0oPpR1BrAhxlsy1Rc&ab_channel=PhoenixNAPGlobalITServices)
- [Developers Portal](https://developers.phoenixnap.com)
- [Knowledge Base](https://phoenixnap.com/kb)
- [Blog](https:/phoenixnap.com/blog)

### Documentation

- [Ansible Galaxy - phoenixNAP](https://galaxy.ansible.com/phoenixnap)
- [API documentation](https://developers.phoenixnap.com/docs/bmc/1/overview)

### Contact phoenixNAP

Get in touch with us if you have questions or need help with Bare Metal Cloud.

<p align="left">
  <a href="https://twitter.com/phoenixNAP">Twitter</a> •
  <a href="https://www.facebook.com/phoenixnap">Facebook</a> •
  <a href="https://www.linkedin.com/company/phoenix-nap">LinkedIn</a> •
  <a href="https://www.instagram.com/phoenixnap">Instagram</a> •
  <a href="https://www.youtube.com/user/PhoenixNAPdatacenter">YouTube</a> •
  <a href="https://developers.phoenixnap.com/support">Email</a> 
</p>

<p align="center">
  <br>
  <a href="https://phoenixnap.com/bare-metal-cloud"><img src="https://user-images.githubusercontent.com/81640346/115243282-0c773b80-a123-11eb-9de7-59e3934a5712.jpg" alt="phoenixnap Bare Metal Cloud"></a>
</p>
