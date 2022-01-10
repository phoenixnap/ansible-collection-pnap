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
module: reservation

short_description: Create reservation on phoenixNAP Bare Metal Cloud.
description:
    - Creates new package reservation for authenticated account.
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
  sku:
    description: The sku code of product pricing plan.
    type: str
    required: true
  auto_renew:
    description: A flag indicating whether the reservation will auto-renew. ALL reservations with the given SKU will be affected.
    type: bool
  convert:
    description: new SKU. All reservations with the given SKU will be converted to new ones.
    type: str
  state:
    description: Indicate desired state of the target.
    default: present
    choices: ['present']
    type: str

'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

# Create a reservation

- name: Create new reservation
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  collections:
    - phoenixnap.bmc
  tasks:
  - phoenixnap.bmc.reservation:
      client_id: "{{clientId}}"
      client_secret: "{{clientSecret}}"
      sku: XXX-XXX-XXX
      auto_renew: true
      state: present
    register: output
  - name: Print the reservation information
    debug:
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
        description: The product category.
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
        description: Reservations created with initial invoice model ON_CREATION will be invoiced on same date when reservation is created.
        returned: always
        type: str
        sample: ON_CREATION
      startDateTime:
        description: The point in time (in UTC) when the reservation starts..
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
        description: A flag indicating whether the reservation will auto-renew
        returned: always
        type: bool
        sample: true
      sku:
        description: The sku that will be applied to this reservation. It is useful to find out the price by querying the /product endpoint.
        returned: always
        type: str
        sample: XXX-XXX-XXX
      price:
        description: Reservation price
        returned: always
        type: int
        sample: 175
      priceUnit:
        description: The unit to which the price applies.
        returned: always
        type: str
        sample: HOUR
      assignedResourceId:
        description: The resource ID currently being assigned to Reservation.
        returned: always
        type: str
        sample: 83604275-bdba-490a-b87a-978e8dffdb14
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, RESERVATION_API

import os
import json

ALLOWED_STATES = ["present"]


def get_existing_reservations(module):
    response = requests_wrapper(RESERVATION_API, module=module)
    return response.json()


def change_autorenew_state(reservation, auto_renew):
    renew_action = 'enable' if auto_renew is True else 'disable'
    data = json.dumps({
        'autoRenewDisableReason': 'Ansible playbook'
    })
    AUTORENEW_API = RESERVATION_API + reservation['id'] + '/actions/auto-renew/' + renew_action
    return requests_wrapper(AUTORENEW_API, method='POST', data=data).json()


def reservation_action(module, state):
    set_token_headers(module)
    sku = module.params['sku']
    auto_renew = module.params['auto_renew']
    changed = False
    existing_reservations = get_existing_reservations(module)
    target_reservations = [er for er in existing_reservations if sku == er['sku']]
    reservations = []

    if state == 'present':
        if module.params['convert']:
            if not target_reservations:
                raise Exception("Reservation with SKU %s doesn't exist." % sku)
            new_sku = module.params['convert']
            data = json.dumps({
                'sku': new_sku
            })

            for tr in target_reservations:
                CONVERT_ENDPOINT = RESERVATION_API + tr['id'] + '/actions/convert'
                reservations.append(requests_wrapper(CONVERT_ENDPOINT, method='POST', data=data).json())
                changed = True
        else:
            if target_reservations:
                for tr in target_reservations:
                    if tr['autoRenew'] != auto_renew:
                        reservations.append(change_autorenew_state(tr, auto_renew))
                        changed = True
                    else:
                        reservations.append(tr)
            else:
                data = json.dumps({
                    'sku': sku
                })
                reservations = requests_wrapper(RESERVATION_API, method='POST', data=data).json()
                if reservations['autoRenew'] != auto_renew:
                    reservations = change_autorenew_state(reservations, auto_renew)
                changed = True

    return{
        'changed': changed,
        'reservations': reservations
    }


def main():
    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            sku=dict(required=True),
            auto_renew=dict(type='bool'),
            convert={},
            state=dict(choices=ALLOWED_STATES, default='present')
        ),
        required_one_of=[('auto_renew', 'convert')]
    )

    if not HAS_REQUESTS:
        module.fail_json(msg='requests is required for this module.')

    if not module.params.get('client_id') or not module.params.get('client_secret'):
        _fail_msg = ("if BMC_CLIENT_ID and BMC_CLIENT_SECRET are not in environment variables, "
                     "the client_id and client_secret parameters are required")
        module.fail_json(msg=_fail_msg)

    state = module.params['state']

    try:
        module.exit_json(**reservation_action(module, state=state))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
