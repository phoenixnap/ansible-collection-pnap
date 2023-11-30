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
module: public_network

short_description: Create/delete public network on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete public network on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/networks/1/overview).

version_added: "1.5.0"

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
    description: The friendly name of this public network.
    type: str
  description:
    description: The description of this public network.
    type: str
  location:
    description:
      - The location of this public network.
      - Once a network is created, it cannot be modified through a playbook
    type: str
  ip_blocks:
    description:
      - A list of IP Blocks that will be associated with this public network.
      - Once a network is created, it cannot be modified through a playbook
    type: list
    elements: dict
    suboptions:
      id:
        type: str
        description: The assigned IP block to the Public Network.
  vlan_id:
    description: The VLAN that will be assigned to this network.
    type: int
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: Create a public network.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Create a public network.
      phoenixnap.bmc.public_network:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        name: Initial public network
        location: PHX
        description: My first public network 1
        ip_blocks:
          - id: 60473a6115e34466c9f8f083
          - id: 616e6ec6d66b406a45ab8797
        state: present
      register: output
    - name: Print the networks information
      ansible.builtin.debug:
        var: output.public_networks

- name: Delete network
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Delete network
      phoenixnap.bmc.public_network:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        name: Initial public network
        state: absent
      register: output
    - name: Print the networks information
      ansible.builtin.debug:
        var: output.public_networks
'''

RETURN = '''
public_networks:
    description: Public ntworks information as list
    returned: success
    type: complex
    contains:
      id:
        description: The public network identifier.
        type: str
        sample: 604721852cf65253d151528b
      vlanId:
        description: The VLAN of this public network.
        type: int
        sample: 10
      memberships:
        description: A list of resources that are members in this public network.
        type: list
        contains:
          resourceId:
            description: The resource identifier.
            type: str
            sample: 603f3e995c18d515cda9c4f8
          resourceType:
            description: The resource's type.
            type: str
            sample: server
          ips:
            description: List of public IPs associated to the resource.
            type: list
            elements: str
            sample: [ "10.111.14.104", "10.111.14.105", "10.111.14.106"]
      name:
        description: The friendly name of this public network.
        type: str
        sample: Sample Network
      location:
        description: The location of this public network.
        type: str
        sample: PHX
      description:
        description: The description of this public network.
        type: str
        sample: Further details on the network.
      createdOn:
        description: Date and time when this public network was created.
        type: str
        sample: "2022-04-05T13:50:30.491Z"
      ipBlocks:
        description: A list of IP Blocks that are associated with this public netwo
        type: list
        contains:
          id:
            description: The IP Block identifier.
            type: str
            sample: 60473a6115e34466c9f8f083
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          check_immutable_arguments, PUBLIC_NETWORK_API)

import os
import json

ALLOWED_STATES = ["present", "absent"]
IMMUTABLE_ARGUMENTS = {'location': 'location'}


def get_existing_networks(module):
    response = requests_wrapper(PUBLIC_NETWORK_API, module=module)
    return response.json()


def network_action(module, state):
    set_token_headers(module)
    changed = False
    existing_networks = get_existing_networks(module)
    new_network_name = module.params['name']
    target_network = next((network for network in existing_networks if network['name'] == new_network_name), 'absent')

    if state == 'present':
        if target_network == 'absent':
            changed = True
            data = json.dumps({
                'name': new_network_name,
                'location': module.params['location'],
                'description': module.params['description'],
                'ipBlocks': module.params['ip_blocks'],
                'vlanId': module.params['vlan_id'],
            })
            if not module.check_mode:
                target_network = requests_wrapper(PUBLIC_NETWORK_API, method='POST', data=data).json()

        else:
            check_immutable_arguments(IMMUTABLE_ARGUMENTS, target_network, module)
            desc = target_network.get('description')
            if desc != module.params['description']:
                changed = True
                data = json.dumps({
                    'name': target_network['name'],
                    'description': module.params['description'],
                })
                if not module.check_mode:
                    target_network = requests_wrapper(PUBLIC_NETWORK_API + target_network['id'], method='PATCH', data=data).json()

    if state == 'absent' and target_network != 'absent':
        changed = True
        if not module.check_mode:
            response = requests_wrapper(PUBLIC_NETWORK_API + target_network['id'], method='DELETE')
            target_network = 'The network [%s] has been deleted.' % new_network_name if len(response.text) == 0 else response.json()

    if target_network == 'absent':
        target_network = 'The network [%s]' % new_network_name + ' is absent'

    return {
        'changed': changed,
        'public_networks': target_network
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            name={},
            description={},
            location={},
            ip_blocks=dict(
                type='list',
                elements='dict',
                options=dict(
                    id={}
                )
            ),
            vlan_id=dict(type='int'),
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
        module.exit_json(**network_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
