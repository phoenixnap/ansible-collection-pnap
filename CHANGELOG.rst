============================
Phoenixnap.Bmc Release Notes
============================

.. contents:: Topics

v1.21.0
=======

Minor Changes
-------------

- reservation - add new parameter bring_your_own_license
- server - add new parameter bring_your_own_license

v1.20.0
=======

Minor Changes
-------------

- ip_block - Response parameter documentation updated
- ip_block_info - Response parameter documentation updated
- reservation - Response parameter documentation updated
- reservation_info - Response parameter documentation updated

New Modules
-----------

- phoenixnap.bmc.reservation_transfer - Transfer server reservation

v1.19.0
=======

Minor Changes
-------------

- ip_block - ip_version parameter is added
- public_network - ra_enabled parameter is added, new parameters in docs, cidr, usedIpsCount, raEnabled
- public_network_info - new parameters in docs, cidr, usedIpsCount, raEnabled
- public_network_ip_block - new parameters in docs, cidr, usedIpsCount, raEnabled
- server_public_network - compute_slaac_ip parameter is added

v1.18.0
=======

Minor Changes
-------------

- README - updated to align with the certified collections requirements

New Modules
-----------

- phoenixnap.bmc.bgp_peer_group - Create/delete BGP Peer Group. on phoenixNAP Bare Metal Cloud.
- phoenixnap.bmc.bgp_peer_group_info - Gather information about phoenixNAP BGP Peer Groups owned by account.

v1.17.1
=======

Minor Changes
-------------

- bmc_server - The documentation for inventory module has been updated to meet the Ansible lint requirements
- invoice_info - Updated string formatting for compatibility with older Python versions.

v1.17.0
=======

Minor Changes
-------------

- pnap.py - event endpoint path  corrected
- server - add new parameter datastore_congiguration

New Plugins
-----------

Inventory
~~~~~~~~~

- phoenixnap.bmc.bmc_server - Retrieves list of servers via PhoenixNAP BMC API

New Modules
-----------

- phoenixnap.bmc.invoice_info - List invoices.
- phoenixnap.bmc.transaction_info - List of client's transactions.

v1.16.0
=======

Minor Changes
-------------

- Improved documentation

New Modules
-----------

- phoenixnap.bmc.server_reserved - Provision reserved server.

v1.15.0
=======

Minor Changes
-------------

- The documentation for modules has been updated to meet the Ansible lint requirements

New Modules
-----------

- phoenixnap.bmc.rated_usage_info - Retrieves all rated usage for given time period.
- phoenixnap.bmc.server_reserve - reserve specific server.

v1.14.0
=======

Minor Changes
-------------

- ip_block - multiple descriptions create multiple ip blocks
- storage_network - volumes parameter has new parameter tags added
- storage_network_info - volumes parameter has new parameter tags added

v1.13.0
=======

Minor Changes
-------------

- ip_block_info - add new parameter cidr_block_size

v1.12.0
=======

Minor Changes
-------------

- ip_block - Delete IP Blocks only if count is defined.
- ip_block_info - filter by location, description, state
- server - add new parameter storage_configuration

v1.11.0
=======

Minor Changes
-------------

- server - add new netris_controller parameter
- server - add new netris_softgate parameters
- storage_network - add new parameter client_vlan

New Modules
-----------

- phoenixnap.bmc.public_network_ip_block - add/remove an IP block from a public network.
- phoenixnap.bmc.storage_network_volume - add/remove Volume from a Storage Network.

v1.10.0
=======

Minor Changes
-------------

- ip_block_info - filter by IP Block identifiers
- private_network - The cidr parameter is no longer required
- private_network - new parameter force added

New Modules
-----------

- phoenixnap.bmc.server_ip_block - add/remove an IP block from a server.
- phoenixnap.bmc.server_private_network - add/remove the server to/from a private network
- phoenixnap.bmc.server_public_network - add/remove the server to/from a public network

v1.9.0
======

Minor Changes
-------------

- server - The delete_ip_blocks parameter is required when state is absent
- server - add new parameter force

v1.8.0
======

Minor Changes
-------------

- private_network - add new parameter vlan_id
- public_network - add new parameter vlan_id

v1.7.1
======

Bugfixes
--------

- server - cloud_init_user_data default value added

v1.7.0
======

Minor Changes
-------------

- server - add new parameter cloud_init_user_data

v1.6.0
======

Minor Changes
-------------

- ip_block and server examples updated
- server - add new parameter install_os_to_rams

New Modules
-----------

- phoenixnap.bmc.storage_network - Create/delete storage network on phoenixNAP Bare Metal Cloud.
- phoenixnap.bmc.storage_network_info - Gather information about phoenixNAP BMC storage networks
