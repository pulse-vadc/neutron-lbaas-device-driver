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

from neutron_lbaas._i18n import _
from oslo_config import cfg
from oslo_log import log as logging
from brocade_neutron_lbaas import check_required_settings

LOG = logging.getLogger(__name__)

lbaas_setting_opts = [
    cfg.ListOpt('admin_servers', help=_(
                "List of vTMs in shared cluster (hostnames or IPs)")),
    cfg.BoolOpt('allow_different_host_hint', default=True, help=_(
                'Deploy secondary instances on different compute node. '
                'DO NOT set to True if there is only one compute node '
                '(e.g. DevStack)')),
    cfg.BoolOpt('allow_tenant_customizations', default=False,
               help=_('Allow certain global settings to be overriden on a '
               'per-tanant basis')),
    cfg.ListOpt('configuration_source_ips', help=_(
                'List of IPs from which API calls can be made')),
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
    cfg.StrOpt('keystone_version', default="3",
               help=_('Version of Keystone API to use')),
    cfg.BoolOpt('https_offload', default=True,
                help=_('Enable HTTPS termination')),
    cfg.StrOpt('image_id',
               help=_('Glance ID of vTM image file to provision')),
    cfg.StrOpt('management_mode', default='FLOATING_IP',
               help=_('Whether to use floating IP or dedicated mgmt network')),
    cfg.StrOpt('management_network',
               help=_('Neutron ID of network for admin traffic')),
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
    cfg.StrOpt('primary_az', help=_('Availability Zone for primary vTM')),
    cfg.StrOpt('secondary_az', help=_('Availability Zone for secondary vTM')),
    cfg.BoolOpt('specify_az', default=False, help=_(
                'If set to true, admin can specify which Availibility Zones '
                'the primary and secondary vTMs are deployed in.')),
    cfg.StrOpt('service_endpoint_address',
               help=_('Service Endpoint Address of Services Director cluster')
               ),
    cfg.StrOpt('tenant_customizations_db', help=_(
               'Database connection string for customizations DB '
               '(<db_type>://<username>:<password>@<db_host>/<db_name>)'))
]
services_director_setting_opts = [
    cfg.StrOpt('api_version', default="2.0",
               help=_('Version of Services Director REST API to use')),
    cfg.IntOpt('bandwidth',
               help=_('Bandwidth allowance for vTM instances')),
    cfg.StrOpt('feature_pack',
               help=_('Feature Pack resource for vTM instances')),
    cfg.StrOpt('fla_license', default="universal_v4",
               help=_('FLA license resource to apply to vTM instances')),
    cfg.StrOpt('password',
               help=_('Password of Services Director admin account')),
    cfg.IntOpt('rest_port', default=8100,
               help=_('TCP port that the Services Director REST daemon '
               'listens on')),
    cfg.StrOpt('username', default="admin",
               help=_('Username of Services Director admin account'))
]
vtm_setting_opts = [
    cfg.IntOpt('admin_port', default=9090,
               help=_('Port that the vTM admin interface listens on')),
    cfg.StrOpt('api_version', default="3.10",
               help=_('Version of Stingray REST API to use')),
    cfg.IntOpt('cluster_port', default=9080,
               help=_('Port that the vTM cluster healthchecks on')),
    cfg.BoolOpt('gui_access', default=False,
                help=_('Allow read-only access to the web GUI')),
    cfg.IntOpt('mtu', default=1500,
               help=_('MTU for the vTM instance interfaces')),
    cfg.ListOpt('nameservers',
               help=_('List of nameservers for vTM to use')),
    cfg.StrOpt('password',
               help=_('Password of vTM admin account')),
    cfg.IntOpt('rest_port', default=9070,
               help=_('TCP port that the vTM REST daemon listens on')),
    cfg.IntOpt('ssh_port', default=22,
               help=_('TCP port that the vTM SSH server listens on')),
    cfg.StrOpt('timezone', default="UTC",
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
    import driver_shared_cluster as selected_driver
else:
    check_required_settings({
        "lbaas_settings": {
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
            "service_endpoint_address":
                "Service Endpoint Address of Services Director cluster",
        },
        "services_director_settings": {
            "bandwidth":
                "Amount of bandwidth to allocate to each vTM instance",
            "feature_pack":
                "Name of Services Director feature pack resource to use "
                "for each vTM",
            "fla_license":
                "Name of FLA license resource to use for each vTM",
            "password": "Password for the Services Director admin user"
        },
        "vtm_settings": {
            "nameservers": "List of nameservers for vTM instances to use"
        }
    })
    if cfg.CONF.lbaas_settings.deploy_ha_pairs is True:
        import driver_private_instances_ha as selected_driver
    else:
        import driver_private_instances as selected_driver
device_driver = selected_driver
