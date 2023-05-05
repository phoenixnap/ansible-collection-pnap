============================
Phoenixnap.Bmc Release Notes
============================

.. contents:: Topics


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
