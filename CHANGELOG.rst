============================
Phoenixnap.Bmc Release Notes
============================

.. contents:: Topics


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
