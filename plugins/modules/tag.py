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
module: tag

short_description: Create/delete tag on phoenixNAP Bare Metal Cloud.
description:
    - Create/delete tag on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/tags/1/overview).

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
  name:
    description: The unique name of the tag.
    type: str
  description:
    description: The description of the tag.
    type: str
  is_billing_tag:
    description: Whether or not to show the tag as part of billing and invoices.
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

# Create a tag

- name: Create new tag for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.tag:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: Environment
      description: This tag is used for all resources that need to be assigned to an environment.
      is_billing_tag: false
      state: present
    register: output
  - name: Print the tag information
    debug:
      var: output.tags

# Delete a tag

- name: Delete the tag
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.tag:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: Environment
      state: absent
    register: output
  - name: Print the tag information
    debug:
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
import json

ALLOWED_STATES = ["present", "absent"]


def get_existing_tags(module):
    response = requests_wrapper(TAG_API, module=module)
    return response.json()


def tag_action(module, state):
    set_token_headers(module)
    changed = False
    existing_tags = get_existing_tags(module)
    new_tag_name = module.params['name']
    target_tag = next((network for network in existing_tags if network['name'] == new_tag_name), 'absent')

    if state == 'present':
        if target_tag == 'absent':
            changed = True
            data = json.dumps({
                'name': new_tag_name,
                'isBillingTag': module.params['is_billing_tag'],
                'description': module.params['description'],
            })
            if not module.check_mode:
                target_tag = requests_wrapper(TAG_API, method='POST', data=data).json()
        else:
            desc = target_tag.get('description')
            if desc != module.params['description'] or target_tag['isBillingTag'] != module.params['is_billing_tag']:
                changed = True
                data = json.dumps({
                    'name': target_tag['name'],
                    'description': module.params['description'],
                    'isBillingTag': module.params['is_billing_tag']
                })
                if not module.check_mode:
                    target_tag = requests_wrapper(TAG_API + target_tag['id'], method='PATCH', data=data).json()

    if state == 'absent' and target_tag != 'absent':
        changed = True
        if not module.check_mode:
            target_tag = requests_wrapper(TAG_API + target_tag['id'], method='DELETE').json()

    if target_tag == 'absent':
        target_tag = 'The tag [%s]' % new_tag_name + ' is absent'

    return{
        'changed': changed,
        'tags': target_tag
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            name={},
            description={},
            is_billing_tag=dict(type='bool'),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "present", ["name", "is_billing_tag"]]],
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
        module.exit_json(**tag_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
