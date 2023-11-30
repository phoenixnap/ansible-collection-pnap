#!/usr/bin/python
# (c) 2021, Pavle Jojkic <pavlej@phoenixnap.com> , Goran Jelenic <goranje@phoenixnap.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'certified'
}

DOCUMENTATION = '''
---
module: ssh_key_info

short_description: Gather information about phoenixNAP BMC SSH Keys
description:
    - Gather information about ssh keys available.
    - This module has a dependency on requests

version_added: "0.7.0"

author:
    - Pavle Jojkic (@pajuga) <pavlej@phoenixnap.com>
    - Goran Jelenic (@goranje) <goranje@phoenixnap.com>

options:
  client_id:
    description: Client ID (Application Management)
    type: str
  client_secret:
    description: Client Secret (Application Management)
    type: str
  names:
    description: SSH key names that represent an SSH keys
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all SSH keys
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List all SSH keys information for account
      phoenixnap.bmc.ssh_key_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.ssh_keys

- name: List the SSH key details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List SSH keys information based on the specified names
      phoenixnap.bmc.ssh_key_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        names: [default-key]
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.ssh_keys
'''

RETURN = '''
ssh_keys:
    description: The SSH key information as list
    returned: success
    type: complex
    contains:
      id:
        description: The unique identifier of the SSH key..
        returned: always
        type: str
        sample: 5fa54d1e91867c03a0a7b4a4
      default:
        description: Keys marked as default are always included on server creation and reset unless toggled off in creation/reset request.
        returned: always
        type: bool
        sample: true
      name:
        description: Friendly SSH key name to represent an SSH key.
        returned: always
        type: str
        sample: sshkey-name-01
      key:
        description: SSH key value.
        returned: always
        type: str
        sample: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF9LdAFElNCi...
      fingerprint:
        description: SSH key auto-generated SHA-256 fingerprint.
        returned: always
        type: str
        sample: iL4k5YTrOnzvlxFMN+WU4BPI/QqrMcvvhU0xlfeMwZI
      createdOn:
        description: Date and time of creation.
        returned: always
        type: str
        sample: "2020-03-19T16:39:00Z"
      lastUpdatedOn:
        description: Date and time of last update.
        returned: always
        type: str
        sample: "2020-03-19T16:39:00Z"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, SSH_API

import os


def ssh_key_info(module):
    set_token_headers(module)
    ssh_keys = requests_wrapper(SSH_API, module=module).json()
    filter_ssh_keys = []
    names = module.params['names']

    if names:
        [filter_ssh_keys.append(sh) for sh in ssh_keys if sh['name'] in names]
        ssh_keys = filter_ssh_keys

    return {
        'ssh_keys': ssh_keys
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            names=dict(type='list', elements='str'),
        ),
        supports_check_mode=True,
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    try:
        module.exit_json(**ssh_key_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
