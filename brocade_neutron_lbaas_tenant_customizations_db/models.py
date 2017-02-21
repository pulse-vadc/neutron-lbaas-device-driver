#!/usr/bin/env python

import re
from sqlalchemy import Column, Integer, String, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import validates

BaseTable = declarative_base()

class BrocadeLbaasTenantCustomizations(BaseTable):

    __bind_key__ = "brcdlbaastenantcust"
    __tablename__ = "brocade_lbaas_tenant_customizations"

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
        return "<BrocadeLbassTenantCustomizations %s: %s %s:%s=%s>" % (
            self.uid, self.tenant_id, self.config_section, 
            self.parameter, self.value
        )
