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
module: public_network_info

short_description: Gather information about phoenixNAP BMC public networks
description:
    - Gather information about public networks available.
    - This module has a dependency on requests

version_added: "1.5.0"

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
    description: The friendly name of this private network.
    type: list
    elements: str
  location:
    description: If present will filter the result by the given location of the Public Networks.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all networks
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List all public networks information for account
      phoenixnap.bmc.public_network_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.public_networks

- name: List the network details
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List public networks information based on the specified names
      phoenixnap.bmc.public_network_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        names: Initial public network
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.public_networks
'''

RETURN = '''
public_networks:
    description: Public ntworks information as list
    returned: success
    type: complex
    contains:
      id:
        description: The public network identifier.
        type: str
        sample: 604721852cf65253d151528b
      vlanId:
        description: The VLAN of this public network.
        type: int
        sample: 10
      memberships:
        description: A list of resources that are members in this public network.
        type: list
        contains:
          resourceId:
            description: The resource identifier.
            type: str
            sample: 603f3e995c18d515cda9c4f8
          resourceType:
            description: The resource's type.
            type: str
            sample: server
          ips:
            description: List of public IPs associated to the resource.
            type: list
            elements: str
            sample: [ "10.111.14.104", "10.111.14.105", "10.111.14.106"]
      name:
        description: The friendly name of this public network.
        type: str
        sample: Sample Network
      location:
        description: The location of this public network.
        type: str
        sample: PHX
      description:
        description: The description of this public network.
        type: str
        sample: Further details on the network.
      createdOn:
        description: Date and time when this public network was created.
        type: str
        sample: "2022-04-05T13:50:30.491Z"
      ipBlocks:
        description: A list of IP Blocks that are associated with this public netwo
        type: list
        contains:
          id:
            description: The IP Block identifier.
            type: str
            sample: 60473a6115e34466c9f8f083
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, PUBLIC_NETWORK_API

import os


def public_network_info(module):
    set_token_headers(module)
    params = {
        'location': module.params['location']
    }
    public_networks = requests_wrapper(PUBLIC_NETWORK_API, params=params, module=module).json()
    filter_networks = []
    names = module.params['names']

    if names:
        [filter_networks.append(pn) for pn in public_networks if pn['name'] in names]
        public_networks = filter_networks

    return {
        'public_networks': public_networks
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            names=dict(type='list', elements='str'),
            location={},
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
        module.exit_json(**public_network_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
