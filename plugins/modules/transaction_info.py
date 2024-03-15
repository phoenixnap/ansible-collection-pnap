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
module: transaction_info

short_description: List of client's transactions.
description:
    - List transactions.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/payments/1/routes/transactions/get).

version_added: "1.17.0"

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
  limit:
    description: The limit of the number of results returned.
    type: int
  offset:
    description: The number of items to skip in the results.
    type: int
  sort_direction:
    description: Sort Given Field depending on the desired direction.
    type: str
  sort_field:
    description: If a sortField is requested, pagination will be done after sorting.
    type: str
  from_date:
    description: From the date and time (inclusive) to filter transactions by.
    type: str
  to_date:
    description: To the date and time (inclusive) to filter transactions by.
    type: str
  transaction_id:
    description: The transaction identifier.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all transactions.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List transactions.
      phoenixnap.bmc.transaction_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.transactions

- name: Get transaction details.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Get transaction details.
      phoenixnap.bmc.transaction_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        transaction_id: 0a1b2c3d4f5g6h7i8j9k
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.transactions
'''

RETURN = '''
transactions:
    description: The transactions information as list
    returned: success
    type: dict
    contains:
      limit:
        description: Maximum number of items in the page (actual returned length can be less).
        type: int
        sample: 5
      offset:
        description: The number of returned items skipped.
        type: int
        sample: 25
      total:
        description: The total number of records available for retrieval.
        type: int
        sample: 400
      results:
        description: transaction details
        type: list
        contains:
          id:
            description: The Transaction ID.
            type: str
            sample: 5fa54d1e91867c03a0a7b4a4
          status:
            description: The Transaction status.
            type: str
            sample: FAILED
          details:
            description: Details about the transaction.
            type: str
            sample: Transaction failed due to credit card expiration.
          amount:
            description: The transaction amount.
            type: float
            sample: 10.99
          date:
            description: Date and time when transaction was created.
            type: str
          metadata:
            description: Transaction's metadata.
            type: str
          cardPaymentMethodDetails:
            description: Card payment details of a transaction.
            type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, TRANSACTION_API

import os


def transaction_info(module):
    set_token_headers(module)
    transaction_id = module.params['transaction_id']

    params = {
        'limit': module.params['limit'],
        'offset': module.params['offset'],
        'sortDirection': module.params['sort_direction'],
        'sortField': module.params['sort_field'],
        'from': module.params['from_date'],
        'to': module.params['to_date'],
    }

    if transaction_id:
        transactions = requests_wrapper(TRANSACTION_API + transaction_id, module=module).json()
    else:
        transactions = requests_wrapper(TRANSACTION_API, params=params, module=module).json()

    return {
        'transactions': transactions
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            limit=dict(type='int'),
            offset=dict(type='int'),
            sort_direction={},
            sort_field={},
            from_date={},
            to_date={},
            transaction_id={},
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
        module.exit_json(**transaction_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
