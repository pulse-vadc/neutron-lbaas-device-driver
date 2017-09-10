#!/usr/bin/python
#
# Copyright 2017 Brocade Communications Systems, Inc.  All rights reserved.
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
# Matthew Geldert (mgeldert@pulsesecure.net), Pulse Secure, LLC
#

import re
from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates

BaseTable = declarative_base()

class PulseLbaasTenantCustomizations(BaseTable):

    __bind_key__ = "pulselbaastenantcust"
    __tablename__ = "pulse_lbaas_tenant_customizations"

    """ Unique ID for each record. """
    uid = Column(Integer, primary_key=True)

    """ Keystone ID of the tenant to customize settings for. """
    tenant_id = Column(String(36), nullable=False)

    """ Configuration section of customized parameter. """
    config_section = Column(Enum(
        "lbaas_settings", "vtm_settings", "services_director_settings"
    ), nullable=False)

    """ Configuration parameter name for customization. """
    parameter = Column(String(100), nullable=False)

    """ Value for customization. """
    value = Column(String(100), nullable=False)

    @validates("tenant_id")
    def validate_tenant_id(self, key, tenant_id):
        """ Ensure the specified tenant ID is of the correct format. """
        tenant_id = tenant_id.replace("-", "")
        if re.match("[0-9a-f]{32}", tenant_id):
            return tenant_id
        raise Exception("Invalid tenant_id")

    def __repr__(self):
        return "<PulseLbassTenantCustomizations %s: %s %s:%s=%s>" % (
            self.uid, self.tenant_id, self.config_section, 
            self.parameter, self.value
        )
