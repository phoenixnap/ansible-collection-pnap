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
module: product_info

short_description: Gather information about phoenixNAP BMC products
description:
    - Gather information about products.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/bmc-billing/1/routes/products/get).

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
  product_code:
    description: Product code.
    type: str
  product_category:
    description: Product category.
    type: str
  sku_code:
    description: Sku code.
    type: str
  location:
    description: Location.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Information about all products
- name: Information about all products
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.product_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
    register: output
  - name: Print the gathered infos
    debug:
      var: output.products

# Information about all server products at a specific location
- name: Information about all server products at the Phoenix location
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.product_info:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      product_category: SERVER
      location: PHX
    register: output
  - name: Print the gathered infos
    debug:
      var: output.products

'''

RETURN = '''
products:
    description: The products information as list
    returned: success
    type: list
    contains:
      productCode:
        description: The code identifying the product. This code has significant across all locations.
        returned: always
        type: str
        sample: d1.tiny
      productCategory:
        description: The product category.
        returned: always
        type: str
        sample: server
      plans:
        description: The pricing plans available for this product.
        returned: always
        type: list
        contains:
          sku:
            description: The SKU identifying this pricing plan.
            type: str
            sample: XXX-XXX-XXX
          skuDescription:
            description: Description of this pricing plan.
            type: str
            sample: Hourly Rate for d1.tiny in Phoenix
          location:
            description: The code identifying the location.
            type: str
            sample: PHX
          pricingModel:
            description: The pricing model.
            type: str
            sample: HOURLY
          price:
            description: The SKU identifying this pricing plan.
            type: float
            sample: 0.22
          priceUnit:
            description: The unit to which the price applies.
            type: str
            sample: MONTH
          correlatedProductCode:
            description: Product code of the product this product is correlated with.
            type: str
            sample: d1.tiny
          packageQuantity:
            description: Package size per month.
            type: int
            sample: 50
          packageUnit:
            description: Package size unit.
            type: str
            sample: GB
      metadata:
        description: Details of the server product.
        type: list
        contains:
          ramInGb:
            description: RAM in GB.
            type: int
            sample: 256
          cpu:
            description: CPU name.
            type: str
            sample: Dual Gold 6258R
          cpuCount:
            description: Number of CPUs.
            type: int
            sample: 56
          coresPerCpu:
            description: CPU frequency in GHz.
            type: int
            sample: 2
          cpuFrequency:
            description: CPU frequency in GHz.
            type: float
            sample: 0.22
          network:
            description: Server network.
            type: str
            sample: 2x 25Gbps
          storage:
            description: Server storage.
            type: str
            sample: 2x 2TB NVMe

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, PRODUCT_API

import os


def product_info(module):
    set_token_headers(module)

    params = {
        'productCode': module.params['product_code'],
        'productCategory': module.params['product_category'],
        'skuCode': module.params['sku_code'],
        'location': module.params['location'],
    }

    products = requests_wrapper(PRODUCT_API, params=params, module=module).json()

    return{
        'products': products
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            product_code={},
            product_category={},
            sku_code={},
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
        module.exit_json(**product_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
