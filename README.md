# THIS IS A BETA RELEASE AND IS UNSUPPORTED.  DO NOT USE IN A PRODUCTION ENVIRONMENT #

## Brocade vADC device driver for OpenStack Neutron LBaaS ##
This is the OpenStack Neutron LBaaS device driver for Brocade Virtual Application Delivery Controller (formerly SteelApp).  It plugs into the Brocade LBaaS driver which has shipped with OpenStack since the Kilo release.

### Version ###
This is release version **kilo/beta**.

***Brocade recommend you always use the most recent version of the driver for any given OpenStack release.***

### Changelog ###
2016-03-23:
* Global option to apply the Listener object's "connection_limit" parameter to concurrent connections rather than requests per second
* Fixes a bug that prevents a Listener binding to port 22 in HA configurations

2015-11-17:
* Support for deployment models that make use of Brocade Services Director and dynamically created Traffic Manager instances
* Support for Keystone API v2.0

Initial driver release:
* Full support for LBaaS v2 API/object model
* Utilizes a shared HA cluster of Brocade vTMs to provide LBaaS services

### Installation ###
For details on how to install and configure the driver, please see the [deployment guide](Deployment-Guide.pdf).
