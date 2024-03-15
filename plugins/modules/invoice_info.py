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
module: invoice_info

short_description: List invoices.
description:
    - List invoices.
    - This module has a dependency on requests
    - API is documented at U(https://developers.phoenixnap.com/docs/invoicing/1/routes/invoices/get).

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
  number:
    description: A user-friendly reference number assigned to the invoice.
    type: str
  status:
    description: Payment status of the invoice.
    type: str
  sent_on_from:
    description: Minimum value to filter invoices by sent on date.
    type: str
  sent_on_to:
    description: Maximum value to filter invoices by sent on date.
    type: str
  limit:
    description: The limit of the number of results returned. The number of records returned may be smaller than the limit.
    type: int
  offset:
    description: The number of items to skip in the results.
    type: int
  sort_field:
    description: If a sortField is requested, pagination will be done after sorting. Default sorting is by number.
    type: str
  sort_direction:
    description: Sort Given Field depending on the desired direction. Default sorting is descending.
    type: str
  invoice_id:
    description:
      - The unique resource identifier of the Invoice.
      - Can be used either alone or in conjunction with the "generate_pdf" and "save_as" parameters.
    type: str
  generate_pdf:
    description: Generate invoice details as PDF. The invoice_id parameter is required for this operation.
    type: bool
    default: False
  save_as:
    description:
      - Save PDF to a specified destination with a specified file name.
      - If not defined, the PDF will be saved in the same directory as the playbook, with the filename set to the invoice_id parameter.
    type: str
'''

EXAMPLES = '''
# All the examples assume that you have file config.yaml with your 'clientId' and 'clientSecret'
# in location: ~/.pnap/config.yaml

- name: List all invoices.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: List invoices.
      phoenixnap.bmc.invoice_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.invoices

- name: Get invoice details.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Get invoice details.
      phoenixnap.bmc.invoice_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        invoice_id: 5fa54d1e91867c03a0a7b4a4
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.invoices

- name: Generate the invoice details as a PDF and save it in the same directory as the playbook
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Generate invoice details as PDF.
      phoenixnap.bmc.invoice_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        invoice_id: 5fa54d1e91867c03a0a7b4a4
        generate_pdf: true
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.invoices
- name: Generate invoice details as a PDF and specify the save destination using the save_as parameter.
  hosts: localhost
  gather_facts: false
  vars_files:
    - ~/.pnap/config.yaml
  tasks:
    - name: Generate invoice details as PDF.
      phoenixnap.bmc.invoice_info:
        client_id: "{{ clientId }}"
        client_secret: "{{ clientSecret }}"
        invoice_id: 5fa54d1e91867c03a0a7b4a4
        generate_pdf: true
        save_as: /home/ubuntu/my_invoice.pdf
      register: output
    - name: Print the gathered infos
      ansible.builtin.debug:
        var: output.invoices
'''

RETURN = '''
invoices:
    description: The invoices information as list
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
        description: invoice details
        type: list
        contains:
          id:
            description: The unique resource identifier of the Invoice.
            type: str
            sample: 5fa54d1e91867c03a0a7b4a4
          number:
            description: A user-friendly reference number assigned to the invoice.
            type: str
            sample: 34440-2488782
          currency:
            description: The currency of the invoice.
            type: str
            sample: EUR
          amount:
             description: The invoice amount.
             type: float
             sample: 100.99
          outstandingAmount:
            description: The invoice outstanding amount.
            type: float
          status:
            description: The status of the invoice.
            type: str
          sentOn:
            description: Date and time when the invoice was sent.
            type: str
          dueDate:
            description: Date and time when the invoice payment is due.
            type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.phoenixnap.bmc.plugins.module_utils.pnap import set_token_headers, HAS_REQUESTS, requests_wrapper, INVOICE_API

import os


def invoice_info(module):
    set_token_headers(module)
    invoice_id = module.params['invoice_id']

    params = {
        'number': module.params['number'],
        'status': module.params['status'],
        'sentOnFrom': module.params['sent_on_from'],
        'sentOnTo': module.params['sent_on_to'],
        'limit': module.params['limit'],
        'offset': module.params['offset'],
        'sortField': module.params['sort_field'],
        'sortDirection': module.params['sort_direction'],
    }

    if invoice_id and module.params['generate_pdf']:
        save_as = module.params['save_as'] or f'./{invoice_id}.pdf'
        response = requests_wrapper(INVOICE_API + invoice_id + "/actions/generate-pdf", method="POST", module=module)
        if response.status_code == 200:
            with open(save_as, 'wb') as file:
                file.write(response.content)
            invoices = 'PDF file saved successfully: ' + save_as
        else:
            raise Exception('Failed to download PDF. Status code: ' + response.status_code)
    elif invoice_id:
        invoices = requests_wrapper(INVOICE_API + invoice_id, module=module).json()
    else:
        invoices = requests_wrapper(INVOICE_API, params=params, module=module).json()

    return {
        'invoices': invoices
    }


def main():

    module = AnsibleModule(
        argument_spec=dict(
            client_id=dict(default=os.environ.get('BMC_CLIENT_ID'), no_log=True),
            client_secret=dict(default=os.environ.get('BMC_CLIENT_SECRET'), no_log=True),
            number={},
            status={},
            sent_on_from={},
            sent_on_to={},
            limit=dict(type='int'),
            offset=dict(type='int'),
            sort_field={},
            sort_direction={},
            invoice_id={},
            generate_pdf=dict(type='bool', default=False),
            save_as={},
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
        module.exit_json(**invoice_info(module))
    except Exception as e:
        module.fail_json(msg='failed: %s' % to_native(e))


if __name__ == '__main__':
    main()
