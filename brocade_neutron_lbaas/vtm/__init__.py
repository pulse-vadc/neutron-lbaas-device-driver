#!/usr/bin/env python
#
# Copyright 2014 Brocade Communications Systems, Inc.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Matthew Geldert (mgeldert@brocade.com), Brocade Communications Systems,Inc.
#

from oslo.config import cfg
from oslo_log import log as logging
from brocade_neutron_lbaas import check_required_settings

LOG = logging.getLogger(__name__)

lbaas_setting_opts = [
    cfg.ListOpt('admin_ips', default=None,
               help=_('List of vTM or Services Director IPs')),
    cfg.ListOpt('admin_servers',
               help=_('List of admin server (SDs or vTMs) hostnames')),
    cfg.BoolOpt('deploy_ha_pairs', default=False, help=_(
                'If set to True, an HA pair of vTMs will be deployed in '
                'the PER_TENANT and PER_LOADBALANCER deployment models. '
                'If False, single vTM insatnces are deployed')),
    cfg.StrOpt('deployment_model', help=_(
               'SHARED for a shared pool of vTMs. '
               'PER_TENANT for deploying private vTM instance per tenant. '
               'PER_LB for deploying private vTM instance per loadbalancer'
               )),
    cfg.StrOpt('flavor_id',
               help=_('ID of flavor to use for vTM instance')),
    cfg.StrOpt('image_id',
               help=_('Glance ID of vTM image file to provision')),
    cfg.StrOpt('management_mode', default='FLOATING_IP',
               help=_('Whether to use floating IP or dedicated mgmt network')),
    cfg.StrOpt('management_network',
               help=_('Neutron ID of network for admin traffic')),
    cfg.StrOpt('name_resolution_plugin', default='hosts',
               help=_('Plugin to manipulate name resolution mechanism')),
    cfg.ListOpt('neutron_servers', default=None,
               help=_('List of Neutron Server hostnames')),
    cfg.IntOpt('passive_vtms', default=1,
               help=_('Number of passive vTMs to add to TrafficIP groups')),
    cfg.ListOpt('ports',
               help=_('Neutron port IDs of Stingray traffic-handling ports')),
    cfg.StrOpt('openstack_password',
               help=_('Password of OpenStack admin account')),
    cfg.StrOpt('openstack_username', default="admin",
               help=_('Username of OpenStack admin account')),
    cfg.StrOpt('vtm_domain',
               help=_('Domain to append to hostname to get FQDN'))
]
services_director_setting_opts = [
    cfg.StrOpt('api_version', default="1.5",
               help=_('Version of Services Director REST API to use')),
    cfg.IntOpt('bandwidth',
               help=_('Bandwidth allowance for vTM instances')),
    cfg.StrOpt('feature_pack',
               help=_('Feature Pack resource for vTM instances')),
    cfg.StrOpt('fla_license',
               help=_('FLA license resource to apply to vTM instances')),
    cfg.StrOpt('password',
               help=_('Password of Services Director admin account')),
    cfg.IntOpt('rest_port', default=8000,
               help=_('TCP port that the Services Director REST daemon '
               'listens on')),
    cfg.StrOpt('username', default="admin",
               help=_('Username of Services Director admin account')),
    cfg.StrOpt('version_resource',
               help=_('Version resource for vTM instances'))
]
vtm_setting_opts = [
    cfg.IntOpt('admin_port', default=9090,
               help=_('Port that the vTM admin interface listens on')),
    cfg.StrOpt('api_version', default="3.3",
               help=_('Version of Stingray REST API to use')),
    cfg.IntOpt('cluster_port', default=9080,
               help=_('Port that the vTM cluster healthchecks on')),
    cfg.BoolOpt('gui_access', default=False,
                help=_('Allow read-only access to the web GUI')),
    cfg.ListOpt('nameservers',
               help=_('List of nameservers for vTM to use')),
    cfg.StrOpt('password',
               help=_('Password of vTM admin account')),
    cfg.IntOpt('rest_port', default=9070,
               help=_('TCP port that the vTM REST daemon listens on')),
    cfg.StrOpt('timezone', default="Europe/London",
               help=_('Timezone to set vTM clock to')),
    cfg.StrOpt('username', default="admin",
               help=_('Username for vTM admin account'))
]
cfg.CONF.register_opts(lbaas_setting_opts, "lbaas_settings")
cfg.CONF.register_opts(services_director_setting_opts,
                       "services_director_settings")
cfg.CONF.register_opts(vtm_setting_opts, "vtm_settings")

if cfg.CONF.lbaas_settings.deployment_model is None:
    raise Exception(_(
        "LBaaS: No value for deployment_model in lbaas_settings. "
        "Either the value is not in the Brocade LBaaS configuration file "
        "or the configuration file was not passed to the neutron server."
    ))

if cfg.CONF.lbaas_settings.deployment_model == "SHARED":
    check_required_settings({
        "lbaas_settings": {
            "admin_servers":
                "List of vTMs in shared cluster (hostnames or IPs)",
            "openstack_password":
                "Password of OpenStack admin user",
            "ports":
                "List of UUIDs of the Neutron ports that connect the "
                "vTM cluster to the shared network"
        },
        "vtm_settings": {
            "api_version": "Version of the vTM REST API to use",
            "password": "Password for the vTM cluster admin user"
        }
    })
    import driver_shared as selected_driver
else:
    check_required_settings({
        "lbaas_settings": {
            "admin_servers":
                "List of vTMs in shared cluster (hostnames or IPs)",
            "flavor_id":
                "Nova flavor to use for vTM instances (name or UUID)",
            "image_id":
                "Glance UUID of the vTM Virtual Appliance image to use",
            "management_network":
                "For MGMT_NET mode, the Neutron UUID of the management "
                "network. For FLOATING_IP mode, the Neutron UUID of the "
                "network on which to raise the floating IPs.",
            "openstack_password":
                "Password of OpenStack admin user",
            "vtm_domain":
                "Domain to add to vTM instance hostnames to make FQDN"
        },
        "services_director_settings": {
            "api_version": "Version of the Services Director REST API to use",
            "bandwidth":
                "Amount of bandwidth to allocate to each vTM instance",
            "feature_pack":
                "Name of Services Director feature pack resource to use "
                "for each vTM",
            "fla_license":
                "Name of FLA license resource to use for each vTM",
            "password": "Password for the Services Director admin user",
            "version_resource":
                "Name of the Services Director version resource to use "
                "for each vTM"
        },
        "vtm_settings": {
            "api_version": "Version of the vTM REST API to use",
            "nameservers": "List of nameservers for vTM instances to use"
        }
    })
    if cfg.CONF.lbaas_settings.deploy_ha_pairs is True:
        import driver_unmanaged_ha as selected_driver
    else:
        import driver_unmanaged as selected_driver
device_driver = selected_driver
