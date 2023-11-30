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
module: server_public_network

short_description: add/remove the server to/from a public network
description:
    - add/remove the server to/from a public network
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
  public_network_id:
    description: The network identifier.
    type: str
    required: true
  ips:
    description:
        - Configurable/configured IPs on the server.
        - At least 1 IP address is required. All IPs must be within the network's range.
        - Setting the force query parameter to true allows you to assign no specific IP addresses by designating an empty array of IPs
          and assign one or more IP addresses which are already configured on other resource(s) in network.
    type: list
    elements: str
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

- name: Add the server to a public network.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Add the server to a public network.
      phoenixnap.bmc.server_public_network:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        server_id: e6afba51-7de8-4080-83ab-0f915570659c
        public_network_id: 60473a6115e34466c9f8f083
        ips:
          - 182.16.0.146
          - 182.16.0.147
        state: present
      register: output
    - name: Print the server public network information
      ansible.builtin.debug:
        var: output.server_public_network

- name: Remove the server from public network.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Remove the server from public network.
      phoenixnap.bmc.server_public_network:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        server_id: e6afba51-7de8-4080-83ab-0f915570659c
        public_network_id: 60473a6115e34466c9f8f083
        state: absent
      register: output
    - name: Print the server public_network information
      ansible.builtin.debug:
        var: output.server_public_network
'''

RETURN = '''
server_public_network:
    description: The specified public_network information
    returned: success
    type: complex
    contains:
      id:
        description: The network identifier.
        returned: always
        type: str
        sample: 603f3b2cfcaf050643b89a4b
      ips:
        description: Configurable/configured IPs on the server.
        returned: always
        type: list
        elements: str
        sample: ["1182.16.0.146", "182.16.0.147"]
      statusDescription:
        description: The status of the assignment to the network.
        returned: always
        type: str
        sample: assigned
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import (set_token_headers, HAS_REQUESTS, requests_wrapper,
                                                                          SERVER_API, remove_empty_elements, wait_for_network_status_change)

import os
import json

ALLOWED_STATES = ["present", "absent"]
API_SUFFIX = "/network-configuration/public-network-configuration/public-networks/"


def get_existing_public_network(server_id, target_public_network_id, module):
    response = requests_wrapper(SERVER_API + server_id, module=module)
    public_networks = response.json()['networkConfiguration']['publicNetworkConfiguration']['publicNetworks']
    existing_public_network = next((pn for pn in public_networks if pn['id'] == target_public_network_id), {})
    return existing_public_network


def server_public_network_action(module, state):
    set_token_headers(module)
    changed = False
    server_id = module.params['server_id']
    target_public_network_id = module.params['public_network_id']
    existing_public_network = get_existing_public_network(server_id, target_public_network_id, module)
    existing_public_network_id = existing_public_network.get('id')

    if state == 'present':
        params = {'force': module.params['force']}
        if existing_public_network_id != target_public_network_id:
            changed = True
            data = remove_empty_elements(json.dumps({
                "id": target_public_network_id,
                "ips": module.params['ips'],
            }))

            if not module.check_mode:
                requests_wrapper(SERVER_API + server_id + API_SUFFIX, method='POST', params=params, data=data).json()
                existing_public_network = wait_for_network_status_change(server_id, target_public_network_id, get_existing_public_network, 'assigned', module)
        else:
            if set(existing_public_network['ips']) != set(module.params['ips']):
                changed = True
                data = json.dumps({"ips": module.params["ips"]})
                if not module.check_mode:
                    requests_wrapper(SERVER_API + server_id + API_SUFFIX + existing_public_network_id, method='PATCH', params=params, data=data).json()
                    existing_public_network = wait_for_network_status_change(server_id, target_public_network_id,
                                                                             get_existing_public_network, 'assigned', module)

    if state == 'absent' and existing_public_network_id == target_public_network_id:
        changed = True
        if not module.check_mode:
            existing_public_network = requests_wrapper(SERVER_API + server_id + API_SUFFIX + target_public_network_id, method="DELETE").json()

    return {
        'changed': changed,
        'server_public_network': existing_public_network
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            server_id=dict(required=True),
            public_network_id=dict(required=True),
            ips=dict(type='list', elements='str'),
            force=dict(type='bool'),
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
        module.exit_json(**server_public_network_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
