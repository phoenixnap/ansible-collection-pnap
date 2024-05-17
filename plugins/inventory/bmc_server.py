# -*- coding: utf-8 -*-

# Copyright (c), Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
---
name: bmc_server
author:
  - Pavle Jojkic (@pajuga)
  - Goran Jelenic (@goranje)
short_description: Retrieves list of servers via PhoenixNAP BMC API
description:
  - PhoenixNAP Bare Metal Cloud inventory plugin
  - Retrieves list of servers via PhoenixNAP BMC API
  - Configuration of this plugin is done with files ending with '(bmc_server).(yaml|yml)'
version_added: '1.17.0'
extends_documentation_fragment:
  - constructed
  - inventory_cache
options:
  client_id:
    description:
      - Client ID (Application Management)
      - Fallback environment variable C(BMC_CLIENT_ID).
    type: str
    env:
      - name: BMC_CLIENT_ID
  client_secret:
    description:
      - Client Secret (Application Management)
      - Fallback environment variable C(BMC_CLIENT_SECRET).
    type: str
    env:
      - name: BMC_CLIENT_SECRET
  hostnames:
    description: What to register as the inventory hostname.
    type: str
    choices:
      - hostname
      - id
      - private_ip
      - public_ip
    default: hostname
  filters:
    description:
      - Filter servers with Jinja2 templates.
      - If not provided, all servers are added to inventory.
    type: list
    elements: str
    default: []
"""

EXAMPLES = """
---
# bmc_server.yml name ending file in YAML format
# Example command line: ansible-inventory -i inventory_bmc_server.yml --list

plugin: phoenixnap.bmc.bmc_server
client_id: yyy-zzzz-yyy
client_secret: yyy-xxxx-yyy

## filtering configuration in inventory file
## plugin: phoenixnap.bmc.bmc_server
# client_id: yyy-zzzz-yyy
# client_secret: yyy-xxxx-yyy
# filters:
#   - '"ASH" in location'
#   - '"ubuntu" in os'

## use server ID as hostname and set ansible_host (public IP) with compose
## also make sure public IP is available:
# plugin: phoenixnap.bmc.bmc_server
# client_id: yyy-zzzz-yyy
# client_secret: yyy-xxxx-yyy
# hostname: id
# strict: true
# compose:
#   ansible_host: publicIpAddresses[0]

## Use the private IP
# plugin: phoenixnap.bmc.bmc_server
# client_id: yyy-zzzz-yyy
# client_secret: yyy-xxxx-yyy
# hostname: id
# compose:
#   ansible_host: privateIpAddresses[0]

## Example with keyed_groups and groups
# plugin: phoenixnap.bmc.bmc_server
# client_id: yyy-zzzz-yyy
# client_secret: yyy-xxxx-yyy
# keyed_groups:
#   - prefix: location
#     key: location
# groups:
#   Ubuntu: "'ubuntu' in os"
#   Centos: "'centos' in os"
"""

RETURN = r""" # """

import os

from ansible.errors import AnsibleError
from ansible.module_utils._text import to_native
from ansible.plugins.inventory import (BaseInventoryPlugin, Cacheable, Constructable)

from ..module_utils.pnap import SERVER_API, set_token_headers, requests_wrapper


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    NAME = 'phoenixnap.bmc.bmc_server'

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('bmc_server.yaml', 'bmc_server.yml')):
                valid = True
            else:
                self.display.vvv(
                    "Skipping due to inventory configuration file name mismatch. "
                    "Valid filename endings: "
                    "bmc_server.yaml, bmc_server.yml"
                )
        return valid

    def _get_host_display(self, server, host_display, values):
        host = None
        if host_display in ['hostname', 'id']:
            host = server[host_display]
        elif host_display == 'private_ip':
            host = server['privateIpAddresses'][0]
        else:
            host = server['publicIpAddresses'][0]

        if values.count(host) > 1:
            host += ' [id:' + server['id'] + ']'

        return host

    def _get_hostnames_all_values(self, hostnames, servers):
        if hostnames == 'private_ip':
            hostnames_all_values = []
            for ser in servers:
                try:
                    hostnames_all_values.append(ser['privateIpAddresses'][0])
                except Exception:
                    self.display.vvv(
                        "No private IP address was found for the server: {} ".format(ser['hostname'])
                    )
                    continue
        else:
            hostnames_all_values = [ser['hostname'] for ser in servers]
        return hostnames_all_values

    def _passes_filters(self, filters, variables, host, strict=False):
        if filters and isinstance(filters, list):
            for template in filters:
                try:
                    if not self._compose(template, variables):
                        return False
                except Exception as e:
                    if strict:
                        raise AnsibleError(
                            "Could not evaluate server filter {0} for {1}: {2}".format(
                                template,
                                host,
                                to_native(e),
                            ),
                        )
                    return False
        return True

    def _populate(self, servers):
        self.allowed_hostnames_values = ['hostname', 'id', 'private_ip', 'public_ip']
        hostnames = self.get_option('hostnames')
        if hostnames and hostnames not in self.allowed_hostnames_values:
            raise AnsibleError("Valid options for the hostnames parameter include: {}".format(self.allowed_hostnames_values))

        strict = self.get_option("strict")
        host_filters = self.get_option('filters')
        self.inventory.add_group('bmc_server')
        hostnames_all_values = self._get_hostnames_all_values(hostnames, servers)

        for server in servers:
            host_variables = {}

            for k, v in server.items():
                host_variables[k] = v

            try:
                host_display = self._get_host_display(server, hostnames, hostnames_all_values)
            except Exception:
                self.display.vvv(
                    "Skipping server {} ".format(server['id'])
                )
                continue

            if not self._passes_filters(
                host_filters,
                host_variables,
                host_display,
                strict,  # type: ignore
            ):
                self.display.vvv("Host {0} excluded by filters".format(host_display))
                continue

            self.inventory.add_host(host_display, 'bmc_server')

            for var_name, var_val in host_variables.items():
                self.inventory.set_variable(host_display, var_name, var_val)

            self._set_composite_vars(
                self.get_option("compose"),
                self.inventory.get_host(host_display).get_vars(),  # type: ignore
                host_display,
                strict,  # type: ignore
            )

            self._add_host_to_composed_groups(
                self.get_option("groups"),
                dict(),
                host_display,
                strict,  # type: ignore
            )

            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"),
                dict(),
                host_display,
                strict,  # type: ignore
            )

    def _get_servers(self):
        class AuthModule:
            params = {
                'client_id': self.get_option('client_id') or os.environ.get('BMC_CLIENT_ID'),
                'client_secret': self.get_option('client_secret') or os.environ.get('BMC_CLIENT_SECRET'),
            }
        set_token_headers(AuthModule())
        return requests_wrapper(SERVER_API, module=AuthModule).json()

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)
        self._read_config_data(path=path)

        cache_key = self.get_cache_key(path)
        use_cache = self.get_option("cache") and cache
        update_cache = self.get_option("cache") and not cache

        servers = None
        if use_cache:
            try:
                servers = self._cache[cache_key]
            except KeyError:
                update_cache = True

        if servers is None:
            servers = self._get_servers()

        if update_cache:
            self._cache[cache_key] = servers

        self._populate(servers)
