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
  ip_block_id:
    description: Filter by IP Block identifiers.
    type: list
    elements: str
    aliases: ['ids']
  description:
    description: Filter by IP Block description.
    type: list
    elements: str
  location:
    description: Filter by IP Block location.
    type: list
    elements: str
  status:
    description: Filter by IP Block status.
    type: list
    elements: str
  cidr_block_size:
    description: Filter by IP CIDR Block Size.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List IP blocks
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List IP blocks
      phoenixnap.bmc.ip_block_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
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
      description:
        description: The description of the IP Block.
        type: str
        sample: IP Block #1 used for publicly accessing server #1.
      tags:
        description: The tags assigned if any.
        returned: always
        type: list
        contains:
          id:
            description: The unique id of the tag.
            type: str
            sample: 60ffafcdffb8b074c7968dad
          name:
            description: The name of the tag.
            type: str
            sample: Environment
          value:
            description: The value of the tag assigned to the resource.
            type: str
            sample: PROD
          isBillingTag:
            description: Whether or not to show the tag as part of billing and invoices
            type: bool
            sample: true
          createdBy:
            description: Who the tag was created by.
            type: str
            sample: USER
      isBringYourOwn:
        description: True if the IP block is a bring your own block.
        type: bool
        sample: true
      createdOn:
        description: Date and time when the IP block was created.
        type: str
        sample: "2021-03-13T20:24:32.491Z"
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, IP_API

import os


def ip_blocks_info(module):
    set_token_headers(module)
    ip_block_id = module.params['ip_block_id']
    description = module.params['description']
    location = module.params['location']
    status = module.params['status']
    cidr_block_size = module.params['cidr_block_size']
    ip_blocks = requests_wrapper(IP_API, module=module).json()

    if ip_block_id:
        ip_blocks = [ip for ip in ip_blocks if ip.get('id') in ip_block_id]
    if description:
        ip_blocks = [ip for ip in ip_blocks if ip.get('description') in description]
    if location:
        location = [loc.upper() for loc in location]
        ip_blocks = [ip for ip in ip_blocks if ip.get('location').upper() in location]
    if status:
        status = [s.upper() for s in status]
        ip_blocks = [ip for ip in ip_blocks if ip.get('status').upper() in status]
    if cidr_block_size:
        ip_blocks = [ip for ip in ip_blocks if ip.get('cidrBlockSize').upper() in cidr_block_size]

    return {
        'ip_blocks': ip_blocks
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            location=dict(type='list', elements='str'),
            description=dict(type='list', elements='str'),
            status=dict(type='list', elements='str'),
            cidr_block_size=dict(type='list', elements='str'),
            ip_block_id=dict(type='list', elements='str', aliases=['ids']),
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
