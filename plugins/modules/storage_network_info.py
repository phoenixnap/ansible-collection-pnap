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
module: storage_network_info

short_description: Gather information about phoenixNAP BMC storage networks
description:
    - Gather information about storage networks available.
    - This module has a dependency on requests

version_added: "1.6.0"

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
  location:
    description: If present will filter the result by the given location.
    type: str
  names:
    description: The friendly name of this storage network.
    type: list
    elements: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# List all storage networks information for account
- name: List all storage networks
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.storage_network_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.storage_networks

# List storage networks information based on the specified names
- name: List the storage network details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.storage_network_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      names: My storage network
    register: output
  - name: Print the gathered infos
    debug:
      var: output.storage_networks

'''

RETURN = '''
storage_networks:
    description: The storage networks information as list
    returned: success
    type: complex
    contains:
      id:
        description: Storage network ID.
        returned: always
        type: str
        sample: 603f3b2cfcaf050643b89a4b
      name:
        description: Storage network friendly name.
        returned: always
        type: str
        sample: My storage network
      description:
        description: Storage network description.
        returned: always
        type: str
        sample: My storage network description
      status:
        description: Status of the resource.
        returned: always
        type: str
        sample: READY
      location:
        description: Location of storage network.
        returned: always
        type: str
        sample: PHX
      networkId:
        description: Id of network the storage belongs to.
        returned: always
        type: str
        sample: 603f3b2cfcaf050643b89a4b
      ips:
        description: IP of the storage network.
        returned: always
        type: list
        elements: str
        sample: ["100.64.0.1", "100.64.0.2"]
      createdOn:
        description: Date and time when this storage network was created.
        returned: always
        type: str
      volumes:
        description: Volume for a storage network.
        returned: always
        type: list
        contains:
          id:
            description: Volume ID.
            type: str
            sample: 50dc434c-9bba-427b-bcd6-0bdba45c4dd2
          name:
            description: Volume friendly name.
            type: str
            example: My volume name
          description:
            description: Volume description.
            type: str
            example: My volume description
          path:
            description: Volume's full path. It is in form of /{volumeId}/pathSuffix'.
            type: str
            example: /qjul77ahf5fplr2ba484/shared-docs
          pathSuffix:
            description: Last part of volume's path.
            type: str
            example: /shared-docs
          capacityInGb:
            description: Maximum capacity in GB.
            type: int
            example: 2000
          protocol:
            description: File system protocol. Currently this field should be set to NFS.
            type: str
            example: NFS
          status:
            description: Status of the resource.
            type: str
            example: READY
          createdOn:
            description: Date and time when this volume was created.
            returned: always
            type: str
          permissions:
            description: Permissions for a volume.
            type: dict
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, STORAGE_NETWORK_API

import os


def network_storage_info(module):
    set_token_headers(module)
    params = {
        'location': module.params['location']
    }
    storage_networks = requests_wrapper(STORAGE_NETWORK_API, params=params, module=module).json()
    filter_storage_networks = []
    names = module.params['names']

    if names:
        [filter_storage_networks.append(sn) for sn in storage_networks if sn['name'] in names]
        storage_networks = filter_storage_networks

    return {
        'storage_networks': storage_networks
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            location={},
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
        module.exit_json(**network_storage_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
