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
module: network

short_description: Create/delete network on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete an SSH key on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc/1/overview).

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
    description: The location of this private network.
    type: str
  location_default:
    description: Identifies network as the default private network for the specified location.
    type: bool
    default: false
  cidr:
    description: IP range associated with this private network in CIDR notation.
    type: str
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Create network

- name: Create new network for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My Default Backend Network
      location: PHX
      location_default: true
      description: My Default Backend Network
      cidr: 10.0.0.0/24
      state: present
    register: output
  - name: Print the networks information
    debug:
      var: output.networks

# Delete network

- name: Delete network
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.network:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: My Default Backend Network
      state: absent
    register: output
  - name: Print the networks information
    debug:
      var: output.networks

'''

RETURN = '''
changed:
    description: True if a network was created or removed.
    type: bool
    sample: True
    returned: success
network:
    description: Information about network that was created/removed
    type: dict
    sample: '{"id": "604724a5a807f2d3be8660c7",
              "name": My Default Backend Network,
              "type": "PRIVATE",
              "location": "PHX",
              "locationDefault": true,
              "vlanId": 10,
              "description": "My Default Backend Network",
              "cidr": "10.0.0.0/24",
              "servers": []}'
    returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, NETWORK_API

import os
import json

ALLOWED_STATES = ["present", "absent"]


def get_existing_networks(module):
    response = requests_wrapper(NETWORK_API, module=module)
    return response.json()


def network_action(module, state):
    set_token_headers(module)
    changed = False
    existing_networks = get_existing_networks(module)
    new_network_name = module.params['name']
    target_network = next((network for network in existing_networks if network['name'] == new_network_name), 'absent')

    if state == 'present':
        if target_network == 'absent':
            data = json.dumps({
                'name': new_network_name,
                'location': module.params['location'],
                'locationDefault': module.params['location_default'],
                'description': module.params['description'],
                'cidr': module.params['cidr']
            })
            target_network = requests_wrapper(NETWORK_API, method='POST', data=data).json()
            changed = True
        else:
            desc = target_network.get('description')
            if desc != module.params['description'] or target_network['locationDefault'] != module.params['location_default']:
                data = json.dumps({
                    'name': target_network['name'],
                    'description': module.params['description'],
                    'locationDefault': module.params['location_default']
                })
                target_network = requests_wrapper(NETWORK_API + target_network['id'], method='PUT', data=data).json()
                changed = True

    if state == 'absent' and target_network != 'absent':
        data = json.dumps({
            'private_network_id': target_network['id']
        })
        response = requests_wrapper(NETWORK_API + target_network['id'], method='DELETE', data=data)
        target_network = 'Network deleted' if len(response.text) == 0 else response.json()
        changed = True

    return{
        'changed': changed,
        'networks': target_network
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
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "present", ["name", "location", "cidr"]]]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    state = module.params['state']

    try:
        module.exit_json(**network_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
