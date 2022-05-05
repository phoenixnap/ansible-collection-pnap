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
module: private_network_info

short_description: Gather information about phoenixNAP BMC private networks
description:
    - Gather information about private networks available.
    - This module has a dependency on requests

version_added: "0.11.0"

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
  location:
    description: If present will filter the result by the given location of the Private Networks.
    type: str
  names:
    description: The friendly name of this private network.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# List all private networks information for account
- name: List all private networks
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.private_network_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.private_networks

# List private networks information based on the specified names
- name: List the private network details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.private_network_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      names: [My Default Backend Network]
    register: output
  - name: Print the gathered infos
    debug:
      var: output.private_networks

'''

RETURN = '''
private_networks:
    description: The private networks information as list
    returned: success
    type: complex
    contains:
      id:
        description: The private network identifier.
        returned: always
        type: str
        sample: 604721852cf65253d151528b
      name:
        description: The friendly name of this private network.
        returned: always
        type: str
        sample: Sample Network
      description:
        description: The description of this private network..
        returned: always
        type: str
        sample: Further details on the network
      vlanId:
        description: The VLAN of this private network.
        returned: always
        type: str
        sample: 10
      type:
        description: The type of the private network.
        returned: always
        type: str
        sample: PRIVATE
      location:
        description: The location of this private network.
        returned: always
        type: str
        sample: PHX
      locationDefault:
        description: Identifies network as the default private network for the specified location.
        returned: always
        type: bool
        sample: true
      cidr:
        description: IP range associated with this private network in CIDR notation.
        returned: always
        type: str
        sample: 10.0.0.0/24
      servers:
        description: Server details linked to the Private Network
        returned: always
        type: list
        contains:
          id:
            description: The server identifier.
            type: str
            sample: 603f3e995c18d515cda9c4f8
          ips:
            description: List of private IPs associated to the server.
            type: list
            elements: str
            example: ["10.0.0.2", "10.0.0.3"]
      createdOn:
        description: Date and time when this private network was created.
        returned: always
        type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, PRIVATE_NETWORK_API

import os


def private_network_info(module):
    set_token_headers(module)
    params = {
        'location': module.params['location']
    }
    private_networks = requests_wrapper(PRIVATE_NETWORK_API, params=params, module=module).json()
    filter_private_networks = []
    names = module.params['names']

    if names:
        [filter_private_networks.append(pn) for pn in private_networks if pn['name'] in names]
        private_networks = filter_private_networks

    return{
        'private_networks': private_networks
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            location={},
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
        module.exit_json(**private_network_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
