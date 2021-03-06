## Brocade vADC device driver for OpenStack Neutron LBaaS ##
This is the OpenStack Neutron LBaaS device driver for Brocade Virtual Application Delivery Controller (formerly SteelApp).  

### Version ###
This is driver version **stable/mitaka** update 2017-02.

***Brocade recommend you always use the most recent version of the driver for any given OpenStack release.***

### Requirements ###
* vTM VA 11.1 or higher
* Services Director deployment models require Services Director 2.5 or higher

### Changelog ###

2017-02-22:
* Support for OpenStack Mitaka (not backward-compatible with OpenStack Liberty)
* Support for L7 rules (AKA request-based routing)
* In HA mode, Administrator can specify different Availability Zones for primary and secondary vTM instances
* In HA mode, Nova's _different\_host_ scheduler hint can be used to create the vTM instances on diffrent compute nodes
* Certain global settings can be overriden on a per-tenant basis
* Listener "connection-limit" now refers to the maximum concurrent connections allowed to the listener

2016-02-25:
* Support for OpenStack Liberty (not backward-compatible with OpenStack Kilo)

2015-11-17:
* Support for deployment models that make use of Brocade Services Director and dynamically created Traffic Manager instances
* Support for Keystone API v2.0

Initial driver release:
* Full support for LBaaS v2 API/object model
* Utilizes a shared HA cluster of Brocade vTMs to provide LBaaS services

### Installation ###
For details on how to install and configure the driver, please see the [deployment guide](Deployment-Guide.pdf).
