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
module: server_ip_block

short_description: add/remove an IP block from a server.
description:
    - add/remove an IP block from a server.
    - No actual configuration is performed on the operating system.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc/1/overview).

version_added: "1.10.0"

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
  server_id:
    description: The server's ID.
    type: str
    required: true
  ip_block_id:
    description: The IP block's ID.
    type: str
    required: true
  vlan_id:
    description: The VLAN on which this IP block has been configured within the network switch.
    type: int
  delete_ip_blocks:
    description: Determines whether the IP blocks assigned to the server should be deleted or not.
    default: False
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

- name: Add an IP block to server.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Add an IP block to server.
      phoenixnap.bmc.server_ip_block:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        server_id: e6afba51-7de8-4080-83ab-0f915570659c
        ip_block_id: 60473a6115e34466c9f8f083
        state: present
      register: output
    - name: Print the server ip block information
      ansible.builtin.debug:
        var: output.server_ip_block

- name: Remove an IP block from server.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Remove an IP block from server.
      phoenixnap.bmc.server_ip_block:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        server_id: e6afba51-7de8-4080-83ab-0f915570659c
        ip_block_id: 60473a6115e34466c9f8f083
        delete_ip_blocks: true
        state: absent
      register: output
    - name: Print the server ip block information
      ansible.builtin.debug:
        var: output.server_ip_block
'''

RETURN = '''
server_ip_block:
    description: The specified IP block information
    returned: success
    type: complex
    contains:
      id:
        description: The IP block's ID.
        returned: always
        type: str
        sample: 60473a6115e34466c9f8f083
      vlanId:
        description: The VLAN on which this IP block has been configured within the network switch.
        returned: always
        type: int
        sample: 10
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          SERVER_API, remove_empty_elements)

import os
import json

ALLOWED_STATES = ["present", "absent"]
API_SUFFIX = "/network-configuration/ip-block-configurations/ip-blocks/"


def get_existing_ip_block(server_id, target_ip_block_id, module):
    response = requests_wrapper(SERVER_API + server_id, module=module)
    ip_blocks = response.json()['networkConfiguration']['ipBlocksConfiguration']['ipBlocks']
    existing_ip_block = next((ip for ip in ip_blocks if ip['id'] == target_ip_block_id), {})
    return existing_ip_block


def server_ip_block_action(module, state):
    set_token_headers(module)
    changed = False
    server_id = module.params['server_id']
    target_ip_block_id = module.params['ip_block_id']
    existing_ip_block = get_existing_ip_block(server_id, target_ip_block_id, module)
    existing_ip_block_id = existing_ip_block.get('id')
    target_ip_block = existing_ip_block

    if state == 'present':
        if existing_ip_block_id != target_ip_block_id:
            changed = True
            data = remove_empty_elements(json.dumps({
                "id": target_ip_block_id,
                "vlanId": module.params['vlan_id']
            }))
            if not module.check_mode:
                target_ip_block = requests_wrapper(SERVER_API + server_id + API_SUFFIX, method='POST', data=data).json()
    if state == 'absent' and existing_ip_block_id == target_ip_block_id:
        changed = True
        data = remove_empty_elements(json.dumps({
            "deleteIpBlocks": module.params['delete_ip_blocks']
        }))
        if not module.check_mode:
            target_ip_block = requests_wrapper(SERVER_API + server_id + API_SUFFIX + target_ip_block_id, data=data, method="DELETE").json()

    return {
        'changed': changed,
        'server_ip_block': target_ip_block
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            server_id=dict(required=True),
            ip_block_id=dict(required=True),
            vlan_id=dict(type='int'),
            delete_ip_blocks=dict(type='bool', default=False),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
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
        module.exit_json(**server_ip_block_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
