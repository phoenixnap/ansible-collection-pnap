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
module: ip_address

short_description: Create/delete IP block.
description:
    - Create/delete IP block.
    - An IP Block is a set of contiguous IPs that can be assigned to other resources such as servers.
    - The server module can also create and delete IP Blocks in some cases.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/ips/1/overview).

version_added: "1.2.0"

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
  count:
    description: xx
    type: int
    default: 1
  description:
    description: The description of the IP Block.
    type: str
  location:
    description: IP Block location ID.
    type: str
  cidr_block_size:
    description: CIDR IP Block Size.
    type: str
  ip_block_id:
    description: The IP Block identifier.
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
# and generated SSH key pair in location: ~/.ssh/

# Request an IP Block.

- name: Request an IP Block.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.ip_address:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      location: PHX
      cidr_block_size: /28
      state: present
    register: output
  - name: Print the gathered infos
    debug:
      var: output.ip_addresses

# Delete an IP Block.

- name: Delete an IP Block.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.ip_address:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      ip_block_id: 6047127fed34ecc3ba8402d2
      state: absent
    register: output
  - name: Print the gathered infos
    debug:
      var: output.ip_addresses
'''

RETURN = '''
changed:
    description: True if an IP Block was created or removed.
    type: bool
    sample: True
    returned: success
ip_addresses:
    description: Information about IP Block that were created/removed
    type: complex
    returned: success
    contains:
      id:
        description: IP Block identifier.
        returned: always
        type: str
        sample: 6047127fed34ecc3ba8402d2
      location:
        description: IP Block location ID.
        returned: always
        type: str
        sample: PHX
      cidrBlockSize:
        description: CIDR IP Block Size.
        type: str
        sample: /30
      cidr:
        description: The IP Block in CIDR notation.
        returned: always
        type: str
        sample: 1.1.1.0/31
      status:
        description: The status of the IP Block.
        returned: always
        type: str
        sample: unassigned
      assignedResourceId:
        description: ID of the resource assigned to the IP Block.
        returned: always
        type: str
        sample: 6047127fed34ecc3ba8402d2
      assignedResourceType:
        description: Type of the resource assigned to the IP Block.
        returned: always
        type: str
        sample: server
      description:
        description: The description of the IP Block.
        type: str
        sample: IP Block #1 used for publicly accessing server #1.
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, IP_API

import os
import json

ALLOWED_STATES = ["present", "absent"]


def get_existing_ip_addresses(module):
    response = requests_wrapper(IP_API, module=module)
    return response.json()


def get_matched_ip_addresses(existing_ips, cidr_block_size, location, count):
    match_ips = []
    for ei in existing_ips:
        if ei['cidrBlockSize'] == cidr_block_size and ei['location'] == location:
            match_ips.append(ei)
            count -= 1
    return match_ips, count


def create_ip_addresses(cidr_block_size, location, description, count, module):
    ip_addresses_result = []
    if not module.check_mode:
        data = json.dumps({
            'cidrBlockSize': cidr_block_size,
            'location': location,
            'description': description
        })
        for __ in range(count):
            ip_addresses_result.append(requests_wrapper(IP_API, method='POST', data=data).json())
    else:
        ip_addresses_result.append('%s IP Block(s) will be created. [Cidr: %s | Location: %s]' % (count, cidr_block_size, location))
    return ip_addresses_result


def find_deletion_candidates(match_ips, delete_counter):
    deleteable = []
    [deleteable.append(mi) for mi in match_ips if mi['status'] == 'unassigned']
    if len(deleteable) < delete_counter:
        raise Exception('%s IP Block(s) should be deleted but only %s available for deletion' % (delete_counter, len(deleteable)))
    return deleteable


def delete_ip_addresses(match_ips, count, module, changed):
    ip_addresses_result = []
    for position in range(count):
        changed = True
        data = json.dumps({
            'ipBlockId': match_ips[position]['id']
        })
        if not module.check_mode:
            ip_addresses_result.append(requests_wrapper(IP_API + match_ips[position]['id'], method='DELETE', data=data).json())
        else:
            ip_addresses_result.append('The IP Block with Id %s' % match_ips[position]['id'] + ' will be deleted.')
    return ip_addresses_result, changed


def ip_addresses_action(module, state):
    set_token_headers(module)
    changed = False
    count = module.params['count']
    if count and count < 1:
        raise Exception('The count cannot be less than 0')
    cidr_block_size = module.params['cidr_block_size']
    location = module.params['location']
    description = module.params['description']
    existing_ips = get_existing_ip_addresses(module)
    ip_addresses_result = []

    if state == 'present':
        match_ips, count = get_matched_ip_addresses(existing_ips, cidr_block_size, location, count)
        if count > 0:
            changed = True
            ip_addresses_result = create_ip_addresses(cidr_block_size, location, description, count, module)
        elif count == 0:
            ip_addresses_result = match_ips
        else:
            ids = find_deletion_candidates(match_ips, abs(count))
            ip_addresses_result, changed = delete_ip_addresses(ids, abs(count), module, changed)

    if state == 'absent':
        count = 1
        target_ip_address = next((ip for ip in existing_ips if ip['id'] == module.params['ip_block_id']), 'absent')
        if target_ip_address != 'absent':
            if not module.check_mode:
                ip_addresses_result, changed = delete_ip_addresses([target_ip_address], count, module, changed)
            else:
                ip_addresses_result, changed = delete_ip_addresses([target_ip_address], count, module, changed)
        else:
            ip_addresses_result = 'The IP Block with Id %s' % module.params['ip_block_id'] + ' is absent.'

    return{
        'changed': changed,
        'ip_addresses': ip_addresses_result
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            cidr_block_size={},
            location={},
            ip_block_id={},
            description={},
            count=dict(type='int', default=1),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[
            ["state", "present", ["cidr_block_size", "location"]],
            ["state", "absent", ["ip_block_id"]]
        ],
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
        module.exit_json(**ip_addresses_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
