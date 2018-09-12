## Pulse vADC device driver for OpenStack Neutron LBaaS ##
This is a customized OpenStack Neutron LBaaS device driver for Pulse Virtual 
Application Delivery Controller. This IS NOT a GA driver and should only be
used if you are instructed to do so by a Pulse representative.

### Version ###
This is driver version **cm/kilo-201809** update 2018-09.

***Pulse recommend you always use the most recent version of the driver for any
 given OpenStack release.***

### Requirements ###
* vTM VA 17.2
* Services Director 17.2

### Changelog ###

2018-09:
* Support for per-Loadbalancer vTM deployments
* Support for custom LBaaS Loadbalancer->bandwidth field
* Support for HTTPS offload with Barbican
* Support for reporting Member health status
