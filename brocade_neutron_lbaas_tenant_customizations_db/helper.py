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
# Matthew Geldert (mgeldert@brocade.com), Brocade Communications Systems,Inc.
#

import models
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound

class BrocadeLbaasTenantCustomizationsDatabaseHelper(object):
    """
    PLEASE DO NOT EDIT THE BELOW VARIABLE IN AN ATTEMPT TO CUSTOMIZE OTHER
    PARAMETERS ON A PER TENANT BASIS - YOU WILL BREAK THE DRIVER
    """
    customizable_fields = {
        "lbaas_settings": [
            "deployment_model",
            "primary_az",
            "secondary_az",
            "specify_az",
            "image_id",
            "flavor_id"
        ],
        "vtm_settings": [
            "gui_access",
            "nameservers",
            "ssh_port"
        ],
        "services_director_settings": [
            "bandwidth",
            "feature_pack"
        ]
    }

    def __init__(self, db_path):
        self.engine = create_engine(db_path, pool_recycle=300)
        session_maker = sessionmaker(bind=self.engine)
        self.db = session_maker()

    def create_table(self):
        models.BaseTable.metadata.create_all(self.engine)

    def get_all_tenant_customizations(self, tenant_id):
        customizations = self.db.query(
            models.BrocadeLbaasTenantCustomizations
        ).\
            filter_by(tenant_id=tenant_id).\
            all()
        results = {}
        for record in customizations:
            try:
                results[record.config_section][record.parameter] = record.value
            except KeyError:
                results[record.config_section] = {
                    record.parameter: record.value
                }
        return results

    def get_customization(self, tenant_id, section, parameter):
        self._validate_setting(section, parameter)
        try:
            customization = self.db.query(
                models.BrocadeLbaasTenantCustomizations
            ).\
                filter_by(tenant_id=tenant_id).\
                filter_by(config_section=section).\
                filter_by(parameter=parameter).\
                one()
        except NoResultFound:
            return None
        return customization.value

    def set_customization(self, tenant_id, section, parameter, value):
        self._validate_setting(section, parameter)
        try:
            customization = self.db.query(
                models.BrocadeLbaasTenantCustomizations
            ).\
                filter_by(tenant_id=tenant_id).\
                filter_by(config_section=section).\
                filter_by(parameter=parameter).\
                one()
            customization.value = value
        except NoResultFound:
            self.db.add(models.BrocadeLbaasTenantCustomizations(
                tenant_id=tenant_id,
                config_section=section,
                parameter=parameter,
                value=value
            ))
        self.db.commit()

    def delete_customization(self, tenant_id, section, parameter):
        try:
            customization = self.db.query(
                models.BrocadeLbaasTenantCustomizations
            ).\
                filter_by(tenant_id=tenant_id).\
                filter_by(config_section=section).\
                filter_by(parameter=parameter).\
                one()
            self.db.delete(customization)
            self.db.commit()
        except NoResultFound:
            return False

    def _validate_setting(self, section, parameter):
        try:
            assert parameter in self.customizable_fields[section]
        except AssertionError:
            raise Exception(
                "The parameter '%s' in section '%s' is not customizable." % (
                    parameter, section
            ))
        except KeyError as e:
            raise Exception("No such configuration section as '%s'." % e)
