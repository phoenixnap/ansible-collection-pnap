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
module: reservation_info

short_description: Gather information about phoenixNAP BMC reservations
description:
    - Retrieves all reservations associated with the authenticated account. All date & times are in UTC.
    - This module has a dependency on requests

version_added: "1.0.0"

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
    description: The product category (server, bandwidth, operating-system, public_ip).
    type: str
    required: true
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all server reservations
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List all server reservation
      phoenixnap.bmc.reservation_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        product_category: server
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.reservations
'''

RETURN = '''
reservations:
    description: The reservations information as list
    returned: success
    type: complex
    contains:
      id:
        description: The reservation identifier.
        returned: always
        type: str
        sample: 83604275-bdba-490a-b87a-978e8dffdb14
      productCode:
        description: The code identifying the product. This code has significant across all locations.
        returned: always
        type: str
        sample: d1.tiny
      productCategory:
        description: The product category
        returned: always
        type: str
        sample: server
      location:
        description: The location code.
        returned: always
        type: str
        sample: PHX
      reservationModel:
        description: The Reservation Model.
        returned: always
        type: str
        sample: ONE_MONTH_RESERVATION
      initialInvoiceModel:
        description:
          - Reservations created with initial invoice model ON_CREATION will be invoiced on same date when reservation is created.
          - Reservation created with CALENDAR_MONTH initial invoice model will be invoiced at the beginning of next month.
        returned: always
        type: str
        sample: ONE_MONTH_RESERVATION
      startDateTime:
        description: The point in time (in UTC) when the reservation starts.
        returned: always
        type: str
      endDateTime:
        description: The point in time (in UTC) when the reservation end.
        returned: always
        type: str
      lastRenewalDateTime:
        description: The point in time (in UTC) when the reservation was renewed last.
        returned: always
        type: str
      nextRenewalDateTime:
        description: The point in time (in UTC) when the reservation will be renewed if auto renew is set to true.
        returned: always
        type: str
      autoRenew:
        description: A flag indicating whether the reservation will auto-renew (default is true).
        returned: always
        type: bool
        sample: true
      sku:
        description:
          - The sku that will be applied to this reservation.
          - It is useful to find out the price by querying the /product endpoint.
        returned: always
        type: str
        sample: XXX-XXX-XXX
      price:
        description: Reservation price..
        returned: always
        type: int
        sample: 175
      priceUnit:
        description: The unit to which the price applies..
        returned: always
        type: str
        sample: MONTH
      assignedResourceId:
        description: The resource ID currently being assigned to Reservation..
        returned: always
        type: str
        sample: 83604275-bdba-490a-b87a-978e8dffdb14
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, RESERVATION_API

import os


def reservation_info(module):
    set_token_headers(module)
    data = {
        'productCategory': module.params['product_category'].upper()
    }
    reservations = requests_wrapper(RESERVATION_API, params=data, module=module).json()
    return {
        'reservations': reservations
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            product_category=dict(required=True),
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
        module.exit_json(**reservation_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
