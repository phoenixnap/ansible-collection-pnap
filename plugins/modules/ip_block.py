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
module: ip_block

short_description: Create/delete IP block.
description:
    - Create/delete IP blocks.
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
    description:
      - Specifies the number of IP Blocks.
      - Defined value allow IP blocks to be deleted if they are not used
    type: int
  description:
    description:
      - The description of the IP Block. Using ip_block_id, it can be edited later.
      - Multiple descriptions create/remove multiple IP Blocks.
    type: list
    elements: str
  location:
    description: IP Block location ID.
    type: str
  cidr_block_size:
    description: CIDR IP Block Size.
    type: str
  ip_block_id:
    description:
      - The IP Block identifier.
      - A description can be edited or a certain IP block can be deleted.
    type: str
  tags:
    description: Tags to set to the ip-block.
    type: list
    elements: dict
    suboptions:
      name:
        type: str
        description: The name of the tag.
      value:
        type: str
        description: The value of the tag assigned to the resource.
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

- name: Request an IP Block.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Request an IP Block.
      phoenixnap.bmc.ip_block:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        location: PHX
        cidr_block_size: /28
        state: present
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.ip_blocks

- name: Delete an IP Block.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Delete an IP Block.
      phoenixnap.bmc.ip_block:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        ip_block_id: 6047127fed34ecc3ba8402d2
        state: absent
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.ip_blocks
'''

RETURN = '''
changed:
    description: True if an IP Block was created or removed.
    type: bool
    sample: True
    returned: success
ip_blocks:
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
import json

ALLOWED_STATES = ["present", "absent"]


def get_existing_ip_blocks(module):
    response = requests_wrapper(IP_API, module=module)
    return response.json()


def get_matched_ip_blocks(existing_ips, cidr_block_size, location, count):
    match_ips = []
    for ei in existing_ips:
        if ei['cidrBlockSize'] == cidr_block_size and ei['location'] == location:
            match_ips.append(ei)
            count -= 1
    return match_ips, count


def create_ip_blocks(cidr_block_size, location, description, tags, count, module):
    ip_blocks_result = []
    if not module.check_mode:
        data = json.dumps({
            'cidrBlockSize': cidr_block_size,
            'location': location,
            'description': description,
            'tags': tags,
        })
        for __ in range(count):
            ip_blocks_result.append(requests_wrapper(IP_API, method='POST', data=data).json())
    else:
        ip_blocks_result.append('%s IP Block(s) will be created. [Cidr: %s | Location: %s | Description: %s]' % (count, cidr_block_size, location, description))
    return ip_blocks_result


def find_deletion_candidates(match_ips, delete_counter):
    deleteable = []
    [deleteable.append(mi) for mi in match_ips if mi['status'] == 'unassigned']
    if len(deleteable) < delete_counter:
        raise Exception('%s IP Block(s) should be deleted but only %s available for deletion' % (delete_counter, len(deleteable)))
    return deleteable


def delete_ip_blocks(match_ips, count, module, changed):
    ip_blocks_result = []
    for position in range(count):
        changed = True
        if not module.check_mode:
            ip_blocks_result.append(requests_wrapper(IP_API + match_ips[position]['id'], method='DELETE').json())
        else:
            ip_blocks_result.append('The IP Block with Id %s' % match_ips[position]['id'] + ' will be deleted.')
    return ip_blocks_result, changed


def ip_blocks_action(module, state):
    set_token_headers(module)
    changed = False
    count = 1 if module.params['count'] is None else module.params['count']
    if count and count < 1:
        raise Exception('The count cannot be less than 0')
    cidr_block_size = module.params['cidr_block_size']
    location = module.params['location']
    description = module.params['description']
    tags = module.params['tags']
    ip_block_id = module.params['ip_block_id']
    existing_ips = get_existing_ip_blocks(module)
    ip_blocks_result = []
    existing_descriptions = [ei.get('description') for ei in existing_ips if ei.get('cidrBlockSize') == cidr_block_size and ei.get('location') == location]

    if description and module.params['count'] is None and module.params['ip_block_id'] is None:
        match, no_match = [], []
        for desc in description:
            if desc in existing_descriptions:
                match.append(desc)
                existing_descriptions.remove(desc)
            else:
                no_match.append(desc)

        if state == 'present':
            for item in set(match):
                for ei in existing_ips:
                    if item == ei.get('description'):
                        ip_blocks_result.append(ei)

            if no_match != []:
                changed = True
                if not module.check_mode:
                    for item in no_match:
                        ip_blocks_result.append(create_ip_blocks(cidr_block_size, location, item, tags, 1, module)[0])
                else:
                    for item in no_match:
                        ip_blocks_result.append(
                            {'description': item,
                             'cidrBlockSize': cidr_block_size,
                             'location': location,
                             'status': 'to be created',
                             })
        else:
            if match != []:
                changed = True
                ip_block_ids_for_deletion = []
                for item in set(match):
                    for ei in existing_ips:
                        if item == ei.get('description'):
                            ip_block_ids_for_deletion.append(ei.get('id'))

                if not module.check_mode:
                    for id in ip_block_ids_for_deletion:
                        ip_blocks_result.append(requests_wrapper(IP_API + id, method='DELETE').json())
                else:
                    for id in ip_block_ids_for_deletion:
                        ip_blocks_result.append('The IP Block with Id %s' % id + ' will be deleted.')
    else:
        if module.params['count'] is not None:
            if description and len(description) > 1:
                raise Exception('Parameter count cannot be used with multiple descriptions')
        if state == 'present':
            if description:
                description = description[0]
            if ip_block_id:
                ip_blocks_result = requests_wrapper(IP_API + ip_block_id).json()
                if description:
                    if ip_blocks_result.get('description') != description:
                        changed = True
                        if not module.check_mode:
                            data = json.dumps({
                                'description': description
                            })
                            ip_blocks_result = requests_wrapper(IP_API + ip_block_id, method='PATCH', data=data).json()
            else:
                match_ips, count = get_matched_ip_blocks(existing_ips, cidr_block_size, location, count)
                if count > 0:
                    changed = True
                    ip_blocks_result = create_ip_blocks(cidr_block_size, location, description, tags, count, module)
                elif count == 0 or module.params['count'] is None:
                    ip_blocks_result = match_ips
                else:
                    ids = find_deletion_candidates(match_ips, abs(count))
                    ip_blocks_result, changed = delete_ip_blocks(ids, abs(count), module, changed)

        if state == 'absent':
            target_ip_block = next((ip for ip in existing_ips if ip['id'] == module.params['ip_block_id']), 'absent')
            if target_ip_block != 'absent':
                if not module.check_mode:
                    ip_blocks_result, changed = delete_ip_blocks([target_ip_block], count, module, changed)
                else:
                    ip_blocks_result, changed = delete_ip_blocks([target_ip_block], count, module, changed)
            else:
                ip_blocks_result = 'The IP Block with Id %s' % module.params['ip_block_id'] + ' is absent.'

    return {
        'changed': changed,
        'ip_blocks': ip_blocks_result
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            cidr_block_size={},
            location={},
            ip_block_id={},
            description=dict(type='list', elements='str'),
            count=dict(type='int'),
            tags=dict(
                type="list",
                elements='dict',
                options=dict(
                    name={},
                    value={}
                )
            ),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        mutually_exclusive=[('count', 'ip_block_id')],
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
        module.exit_json(**ip_blocks_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
