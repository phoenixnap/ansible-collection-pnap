from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import json
from unittest import TestCase
from ansible_collections.phoenixnap.bmc.plugins.modules.server import get_api_params


class TestApiParams(TestCase):
    def test_api_params_for_state_absent(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/deprovision',
            'data': json.dumps(
                {
                    'deleteIpBlocks': True
                }, sort_keys=True)
        }
        self.assertDictEqual(get_api_params(PseudoModule(), 'some_server_id', 'absent'), expected_output)

    def test_api_params_for_state_powered_on(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/power-on',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'powered-on'), expected_output)

    def test_api_params_for_state_powered_off(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/power-off',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'powered-off'), expected_output)

    def test_api_params_for_state_shutdown(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/shutdown',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'shutdown'), expected_output)

    def test_api_params_for_state_rebooted(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/reboot',
            'data': 'null'
        }
        self.assertDictEqual(get_api_params(None, 'some_server_id', 'rebooted'), expected_output)

    def test_api_params_for_state_reset(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/some_server_id/actions/reset',
            'data': json.dumps(
                {
                    'installDefaultSshKeys': True,
                    'sshKeys': 'xxx',
                    'sshKeyIds': '123',
                    'osConfiguration': {
                        'windows': {
                            'rdpAllowedIps': '1.1.1.1'
                        },
                        'esxi': {
                            'managementAccessAllowedIps': '1.1.1.1'
                        }
                    }
                }, sort_keys=True)
        }
        self.assertDictEqual(get_api_params(PseudoModule(), 'some_server_id', 'reset'), expected_output)

    def test_api_params_for_state_present(self):
        expected_output = {
            'method': 'POST',
            'endpoint': 'https://api.phoenixnap.com/bmc/v1/servers/',
            'data': json.dumps({
                'description': 'some description',
                'location': 'PHX',
                'hostname': 'my-server-red',
                'installDefaultSshKeys': True,
                'sshKeys': 'xxx',
                'sshKeyIds': '123',
                'networkType': 'PUBLIC_AND_PRIVATE',
                'os': 'ubuntu/bionic',
                'reservationId': '1',
                'pricingModel': 'HOURLY',
                'type': 's1.c1.small',
                'osConfiguration': {
                    'windows': {
                        'rdpAllowedIps': '1.1.1.1'
                    },
                    'managementAccessAllowedIps': '1.1.1.1',
                    'installOsToRam': False,
                    'cloudInit': {
                        'userData': 'eHh4'
                    }
                },
                'networkConfiguration': {
                    'gatewayAddress': '182.16.0.145',
                    'privateNetworkConfiguration': {
                        'configurationType': 'USE_OR_CREATE_DEFAULT'
                    },
                    'ipBlocksConfiguration': {
                        'configurationType': 'USER_DEFINED',
                        'ipBlocks': [
                            {
                                'id': '11111'
                            }
                        ]
                    }
                }
            }, sort_keys=True)
        }
        self.assertDictEqual(get_api_params(PseudoModule(), 'my-server-red', 'present'), expected_output)


class PseudoModule:
    params = {
        'description': 'some description',
        'location': 'PHX',
        'gateway_address': '182.16.0.145',
        'hostname': 'my-server-red',
        'install_default_sshkeys': True,
        'ssh_key': 'xxx',
        'ssh_key_ids': '123',
        'network_type': 'PUBLIC_AND_PRIVATE',
        'os': 'ubuntu/bionic',
        'reservation_id': '1',
        'pricing_model': 'HOURLY',
        'type': 's1.c1.small',
        'rdp_allowed_ips': '1.1.1.1',
        'management_access_allowed_ips': '1.1.1.1',
        'private_network_configuration_type': 'USE_OR_CREATE_DEFAULT',
        'private_networks': [],
        'tags': [],
        'ip_block_configuration_type': 'USER_DEFINED',
        'ip_block': '11111',
        'delete_ip_blocks': True,
        'public_networks': [],
        'install_os_to_ram': False,
        'cloud_init_user_data': 'xxx'
    }
