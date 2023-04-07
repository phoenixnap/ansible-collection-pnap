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
module: private_network

short_description: Create/delete private network on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete private network on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/networks/1/overview).

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
  name:
    description: The friendly name of this private network.
    type: str
  description:
    description: The description of this private network.
    type: str
  location:
    description:
      - The location of this private network.
      - Once a network is created, it cannot be modified through a playbook
    type: str
  location_default:
    description:
      - Identifies network as the default private network for the specified location.
      - Once a network is created, it cannot be modified through a playbook
    type: bool
    default: false
  cidr:
    description: IP range associated with this private network in CIDR notation.
    type: str
  vlan_id:
    description: The VLAN that will be assigned to this network.
    type: int
  force:
    description:
      - parameter controlling advanced features availability.
      - Currently applicable for networking. It is advised to use with caution since it might lead to unhealthy setups.
    type: bool
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Create private network

- name: Create new private network for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.private_network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My Default Backend Network
      location: PHX
      location_default: true
      description: My Default Backend Network
      cidr: 10.0.0.0/24
      state: present
    register: output
  - name: Print the private network information
    debug:
      var: output.private_networks

# Delete network

- name: Delete private network
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.private_network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My Default Backend Network
      state: absent
    register: output
  - name: Print the private networks information
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
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          check_immutable_arguments, PRIVATE_NETWORK_API)

import os
import json

ALLOWED_STATES = ["present", "absent"]
IMMUTABLE_ARGUMENTS = {'cidr': 'cidr', 'location': 'location'}


def get_existing_private_networks(module):
    response = requests_wrapper(PRIVATE_NETWORK_API, module=module)
    return response.json()


def private_network_action(module, state):
    set_token_headers(module)
    changed = False
    existing_networks = get_existing_private_networks(module)
    new_network_name = module.params['name']
    target_network = next((network for network in existing_networks if network['name'] == new_network_name), 'absent')

    if state == 'present':
        if target_network == 'absent':
            changed = True
            data = json.dumps({
                'name': new_network_name,
                'location': module.params['location'],
                'locationDefault': module.params['location_default'],
                'description': module.params['description'],
                'cidr': module.params['cidr'],
                'vlanId': module.params['vlan_id'],
            })
            if not module.check_mode:
                params = {'force': module.params['force']}
                target_network = requests_wrapper(PRIVATE_NETWORK_API, method='POST', data=data, params=params).json()

        else:
            check_immutable_arguments(IMMUTABLE_ARGUMENTS, target_network, module)
            desc = target_network.get('description')
            if desc != module.params['description'] or target_network['locationDefault'] != module.params['location_default']:
                changed = True
                data = json.dumps({
                    'name': target_network['name'],
                    'description': module.params['description'],
                    'locationDefault': module.params['location_default']
                })
                if not module.check_mode:
                    target_network = requests_wrapper(PRIVATE_NETWORK_API + target_network['id'], method='PUT', data=data).json()

    if state == 'absent' and target_network != 'absent':
        changed = True
        if not module.check_mode:
            response = requests_wrapper(PRIVATE_NETWORK_API + target_network['id'], method='DELETE')
            target_network = 'The network [%s] has been deleted.' % new_network_name if len(response.text) == 0 else response.json()

    if target_network == 'absent':
        target_network = 'The network [%s]' % new_network_name + ' is absent'

    return {
        'changed': changed,
        'private_networks': target_network
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            name={},
            description={},
            location={},
            location_default=dict(type='bool', default=False),
            cidr={},
            vlan_id=dict(type='int'),
            force=dict(type='bool'),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "present", ["name", "location"]]],
        supports_check_mode=True
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    state = module.params['state']

    try:
        module.exit_json(**private_network_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
