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
module: product_availability_info

short_description: Gather information about products availability
description:
    - Gather information about products availability.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc-billing/1/routes/product-availability/get).

version_added: "1.3.0"

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
  product_category:
    description: Product category.
    type: list
    elements: str
  product_code:
    description: Product code.
    type: list
    elements: str
  show_only_min_quantity_available:
    description:
      - Show only locations where product with requested quantity is available or all locations where product is offered.
      - Default value is true
    type: bool
  location:
    description: The location code.
    type: list
    elements: str
  solution:
    description: solution
    type: list
    elements: str
  min_quantity:
    description: Minimal quantity of product needed. Minimum, maximum and default values might differ for different products.
    type: int
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Information about all available products
- name: Information about all products
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.product_availability_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.product_availabilities

# Information about all available server products at a specific location
- name: Information about all server products at the Phoenix location
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.product_availability_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      product_category:
        - SERVER
      location:
        - PHX
    register: output
  - name: Print the gathered infos
    debug:
      var: output.product_availabilities

'''

RETURN = '''
products:
    description: The products information as list
    returned: success
    type: list
    contains:
      productCode:
        description: Product code.
        returned: always
        type: str
        sample: d1.c1.small
      productCategory:
        description: The product category.
        returned: always
        type: str
        sample: server
      locationAvailabilityDetails:
        description: Info about location, solutions and availability for a product.
        returned: always
        type: list
        contains:
          location:
            description: The location code.
            type: list
            sample: PHX
          minQuantityRequested:
            description: Requested quantity.
            type: int
            sample: 2
          minQuantityAvailable:
            description: Is product available in specific location for requested quantity.
            type: bool
            sample: true
          availableQuantity:
            description: Total available quantity of product in specific location. Max value is 10.
            type: int
            sample: 5
          solutions:
            description: Solutions supported in specific location for a product.
            type: list
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, PRODUCT_AVAILABILITY_API

import os


def product_availabilities_info(module):
    set_token_headers(module)

    params = {
        'productCategory': module.params['product_category'],
        'productCode': module.params['product_code'],
        'showOnlyMinQuantityAvailable': module.params['show_only_min_quantity_available'],
        'location': module.params['location'],
        'solution': module.params['solution'],
        'minQuantity': module.params['min_quantity'],
    }

    product_availabilities = requests_wrapper(PRODUCT_AVAILABILITY_API, params=params, module=module).json()

    return{
        'product_availabilities': product_availabilities
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            product_category=dict(type='list', elements='str'),
            product_code=dict(type='list', elements='str'),
            show_only_min_quantity_available=dict(type='bool'),
            location=dict(type='list', elements='str'),
            solution=dict(type='list', elements='str'),
            min_quantity=dict(type='int'),
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
        module.exit_json(**product_availabilities_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
