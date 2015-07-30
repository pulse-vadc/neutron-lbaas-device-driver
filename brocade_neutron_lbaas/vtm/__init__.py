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
    cfg.ListOpt('admin_servers',
               help=_('List of vTM hostnames/IPs')),
    cfg.StrOpt('deployment_model', default="SHARED",
               help=_('SHARED for a shared pool of vTMs')),
    cfg.IntOpt('passive_vtms', default=1,
               help=_('Number of passive vTMs to add to TrafficIP groups')),
    cfg.ListOpt('ports',
               help=_('Neutron port IDs of Stingray traffic-handling ports')),
    cfg.StrOpt('openstack_password',
               help=_('Password of OpenStack admin account')),
    cfg.StrOpt('openstack_username', default="admin",
               help=_('Username of OpenStack admin account'))
]
vtm_setting_opts = [
    cfg.IntOpt('admin_port', default=9090,
               help=_('Port that the vTM admin interface listens on')),
    cfg.StrOpt('api_version', default=3.3,
               help=_('Version of Stingray REST API to use')),
    cfg.StrOpt('password',
               help=_('Password of vTM admin account')),
    cfg.IntOpt('rest_port', default=9070,
               help=_('TCP port that the vTM REST daemon listens on')),
    cfg.StrOpt('username', default="admin",
               help=_('Username for vTM admin account'))
]
cfg.CONF.register_opts(lbaas_setting_opts, "lbaas_settings")
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
    raise Exception(_(
        "Unsupported deployment model. The only deployment model currently "
        "supported is 'SHARED'."
    ))
device_driver = selected_driver
