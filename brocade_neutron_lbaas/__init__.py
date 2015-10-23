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

LOG = logging.getLogger(__name__)

lbaas_setting_opts = [
    cfg.StrOpt(
        'product', default="VTM",
        help=_('Brocade product to use (must be "VTM" for this release)'))
]
cfg.CONF.register_opts(lbaas_setting_opts, "lbaas_settings")


def check_required_settings(required):
    error_msg = "\n\nThe following settings were not found in the " + \
                "Brocade configuration file:\n\n"
    key_missing = False
    for section, required_settings in required.iteritems():
        section_key_missing = False
        error_msg += "Missing from section [%s]:\n" % section
        configured_settings = [
            key for key, value in getattr(cfg.CONF, section).iteritems()
            if value is not None
        ]
        for setting, help_string in required_settings.iteritems():
            if setting not in configured_settings:
                error_msg += "%s: %s\n" % (
                        setting, help_string
                )
                section_key_missing = True
                key_missing = True
        if not section_key_missing:
            error_ms += "Nothing\n"
        error_msg += "\n"
    if key_missing:
        error_msg += "Please ensure that the Brocade configuration file " + \
            "is being passed to the Neutron server with the --config-file " + \
            "parameter, and that the file contains values for the above " + \
            "settings.\n"
        raise Exception(_(error_msg))


if cfg.CONF.lbaas_settings.product is None:
    raise Exception(_(
        "LBaaS: No value for product in lbaas_settings. "
        "Either the value is not in the Brocade LBaaS configuration file "
        "or the configuration file was not passed to the neutron server."
    ))

if cfg.CONF.lbaas_settings.product == "VTM":
    from vtm import device_driver as product_driver
    LOG.info(_("\nBrocade LBaaS plugin loading vTM module..."))
else:
    raise Exception(
        _("Unknown Brocade product '%s'" % cfg.CONF.lbaas_settings.product)
    )
adx_device_driver_v2 = product_driver
