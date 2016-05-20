## Brocade vADC device driver for OpenStack Neutron LBaaS ##
This is the OpenStack Neutron LBaaS device driver for Brocade Virtual Application Delivery Controller (formerly SteelApp).  It plugs into the Brocade LBaaS driver.

### Version ###
This is release version **stable/liberty** update 2016-05-20.

***Brocade recommend you always use the most recent version of the driver for any given OpenStack release.***

### Changelog ###
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
