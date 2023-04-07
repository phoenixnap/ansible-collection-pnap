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
module: ip_block_info

short_description: Gather information about phoenixNAP public IP blocks.
description:
    - Retrieves all public IP blocks associated with the authenticated account.
    - This module has a dependency on requests

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
  ids:
    description: Filter by IP Block identifiers.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# List IP blocks
- name: List IP blocks
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.ip_block_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.ip_blocks
'''

RETURN = '''
ip_blocks:
    description: The ip blocks information as list
    returned: success
    type: complex
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
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, IP_API

import os


def ip_blocks_info(module):
    set_token_headers(module)
    ids = module.params['ids']
    ip_blocks = requests_wrapper(IP_API, module=module).json()

    if ids:
        filter_ip_blocks = []
        [filter_ip_blocks.append(ip) for ip in ip_blocks if ip['id'] in ids]
        ip_blocks = filter_ip_blocks

    return {
        'ip_blocks': ip_blocks
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            ids=dict(type='list', elements='str'),
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
        module.exit_json(**ip_blocks_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
