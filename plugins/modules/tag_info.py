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
module: tag_info

short_description: Gather information about phoenixNAP BMC tags
description:
    - Gather information about tags available.
    - This module has a dependency on requests

version_added: "0.12.0"

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
  names:
    description: The unique name of the tag.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all tags
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List all tags information for account
      phoenixnap.bmc.tag_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.tags

- name: List the tag details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List tags information based on the specified names
      phoenixnap.bmc.tag_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        names: [Environment]
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.tags
'''

RETURN = '''
tags:
    description: The tags information as list
    returned: success
    type: complex
    contains:
      id:
        description: The unique id of the tag.
        returned: always
        type: str
        sample: 604721852cf65253d151528b
      name:
        description: The name of the tag.
        returned: always
        type: str
        sample: Environment
      description:
        description: The description of the tag.
        returned: always
        type: str
        sample: This tag is used for all resources that need to be assigned to an environment.
      isBillingTag:
        description: Whether or not to show the tag as part of billing and invoices.
        returned: always
        type: bool
        sample: true
      resourceAssignments:
        description: The tag's assigned resources.
        returned: always
        type: list
        contains:
          resourceName:
            description: The resource name.
            type: str
            sample: /bmc/servers/60ffafcdffb8b074c7968dad
          value:
            description: The value of the tag assigned to the resource.
            type: str
            sample: DEV
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, TAG_API

import os


def tag_info(module):
    set_token_headers(module)
    tags = requests_wrapper(TAG_API, module=module).json()
    filter_tags = []
    names = module.params['names']

    if names:
        [filter_tags.append(tag) for tag in tags if tag['name'] in names]
        tags = filter_tags

    return {
        'tags': tags
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
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
        module.exit_json(**tag_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
