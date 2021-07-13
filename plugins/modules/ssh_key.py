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
module: ssh_key

short_description: Create/delete an SSH key on PhoenixNAP Bare Metal Cloud.
description:
    - Create/delete an SSH key on phoenixNAP Bare Metal Cloud.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc/1/overview).

version_added: "0.6.0"

author:
    - Pavle Jojkic (@pajuga) <pavlej@phoenixnap.com>
    - Goran Jelenic (@goranje) <goranje@phoenixnap.com>

options:
  client_id:
    description: Client ID (Application Management)
    type: str
    required: true
  client_secret:
    description: Client Secret (Application Management)
    type: str
    required: true
  default:
    default: false
    description: Keys marked as default are always included on server creation and reset unless toggled off in creation/reset request.
    type: bool
  ssh_key:
    description: SSH Key actual key value.
    type: str
  name:
    description: Friendly SSH Key name to represent an SSH key.
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

# Create an SSH Key

- name: Create new SSH Key for account
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.ssh_key:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: mykey
      default: true
      ssh_key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}"
      state: present

# Delete an SSH Key

- name: Delete an SSH Key
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.ssh_key:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      name: mykey
      state: absent

'''

RETURN = '''
changed:
    description: True if a sshkey was created or removed.
    type: bool
    sample: True
    returned: success
ssh_key:
    description: Information about sshkey that were created/removed
    type: dict
    sample: '{"createdOn": "2021-06-09T10:08:22.997Z",
              "default": false,
              "fingerprint": "LOLGe4uptCUyckpjTt54FztvCxV0osG0GfcReRQdlEA",
               "id": "11119316fdac92144089a8493",
               "key": "ssh-rsa BAA#B3NzaC1yc2EAAAADwvo+6sWgRsxOTB0l... user@mycomputer",
               "lastUpdatedOn": "2021-06-09T10:08:22.997Z",
               "name": "mykey"}'
    returned: success
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper

import json

ALLOWED_STATES = ["present", "absent"]
BASE_API = 'https://api.phoenixnap.com/bmc/v1/ssh-keys/'


def get_existing_keys(module):
    response = requests_wrapper(BASE_API, module=module)
    return response.json()


def ssh_keys_action(module, state):
    set_token_headers(module)
    changed = False
    existing_keys = get_existing_keys(module)
    new_key_name = module.params['name']
    target_key = next((key for key in existing_keys if key['name'] == new_key_name), 'missing')

    if state == 'present':
        if target_key == 'missing':
            data = json.dumps({
                'name': new_key_name,
                'default': module.params['default'],
                'key': module.params['ssh_key']
            })
            target_key = requests_wrapper(BASE_API, method='POST', data=data).json()
            changed = True
        else:
            if target_key['default'] != module.params['default']:
                data = json.dumps({
                    'name': target_key['name'],
                    'default': module.params['default']
                })
                target_key = requests_wrapper(BASE_API + target_key['id'], method='PUT', data=data).json()
                changed = True

    if state == 'absent' and target_key != 'missing':
        data = json.dumps({
            'ssh_key_id': target_key['id']
        })
        target_key = requests_wrapper(BASE_API + target_key['id'], method='DELETE', data=data).json()
        changed = True

    return{
        'changed': changed,
        'ssh_key': target_key
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(required=True),
            client_secret=dict(required=True, no_log=True),
            name=dict(),
            default=dict(type='bool', default=False),
            ssh_key=dict(no_log=True),
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_if=[["state", "absent", ["name"]]]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    state = module.params['state']

    try:
        module.exit_json(**ssh_keys_action(module, state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
