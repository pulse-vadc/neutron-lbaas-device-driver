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

from abstract_product import ConfigObject, ConfigObjectList, SubList,\
                             ConfigObjectFactory, ProductInstance
import json


class ServicesDirectorConfigObject(ConfigObject):

    def create_from_config_data(self, data):
        try:
            data = json.loads(data)
        except TypeError:
            pass
        for field, value in data.iteritems():
            setattr(self, field, value)

    def to_dict(self, ignore_properties=None):
        obj_dict = {}
        properties = vars(self).copy()
        ignore = ['name', '_object_type', 'connector', '_parent_queue',
                  '_url_modifiers']
        if ignore_properties:
            ignore += ignore_properties
        try:
            if properties['_is_activatable'] is False \
                and properties['status'] != "Inactive":
                ignore.append('status')
        except KeyError:
            pass
        for p in ignore:
            try:
                del properties[p]
            except KeyError:
                pass
        for field, value in properties.iteritems():
            if isinstance(value, SubList):
                tmp_list = []
                for item in value:
                    tmp_list.append(value.show(item))
                value = tmp_list
            if not field.startswith("_"):
                obj_dict[field] = value
        return obj_dict


class ServicesDirectorUserObject(ServicesDirectorConfigObject):
    def __str__(self):
        return json.dumps(self.to_dict(ignore_properties=["username"]))


class ServicesDirectorManagedInstanceObject(ServicesDirectorConfigObject):
    def start(self):
        self.connector("PUT", '{ "status": "Active" }')
        #self._poll_for_change("status", [ 'Active' ], [ 'Failed to Start' ])
        # Execute thread to keep status up-to-date as it transitions?

    def stop(self):
        self.connector("PUT", '{ "status": "Idle" }')
        #self._poll_for_change("status", [ 'Idle' ], [ 'Failed to Stop' ])

    def delete(self):
        self.connector("PUT", '{ "status": "Deleted" }')
        #self._poll_for_change("status", [ 'Deleted' ], [ 'Failed to Delete' ])


class ServicesDirectorUnmanagedInstanceObject(ServicesDirectorConfigObject):
    _url_modifiers = {
        "PUT": {
            "type": "querystring", "value": "managed=false"
        }
    }

    def start(self):
        self.connector("PUT", '{ "status": "Active" }')
        self.status = "Active"

    def delete(self):
        self.connector("PUT", '{ "status": "Deleted" }')
        self.status = "Deleted"

    def register(self, name, **kwargs):
        pass


class ServicesDirectorLicenseObject(ServicesDirectorConfigObject):

    def get_text(self):
        return self.connector("GET", headers={"Accept": "text/plain"})


class ServicesDirectorConfigObjectList(ConfigObjectList):

    def populate_from_instance(self):
        obj_list = json.loads(self.connector())  # Default args get list
        for obj in obj_list['children']:
            obj_name = obj['name']
            obj_data = self.connector(obj_name)
            try:
                obj_config = json.loads(obj_data)  # Will fail for rules :S
            except ValueError:
                obj_config = obj_data
            self.instantiate(obj_name, config=obj_config)

    def create(self, name, *args, **kwargs):
        new_object = super(ServicesDirectorConfigObjectList, self).create(
            name, *args, **kwargs
        )
        #new_object._poll_for_change("status", [ "Active"], [])
        return new_object

    def activate(self, name):
        self[name].status = "Active"
        self[name].connector(method="PUT", data='{ "status": "Active" }')

    def deactivate(self, name):
        try:
            if self[name]._alternate_deactivate is True:
                self[name].connector(method="PUT", data='{ "active": false }')
                self[name].active = False
                return
        except AttributeError:
            pass
        self[name].connector(method="PUT", data='{ "status": "Inactive" }')
        self[name].status = "Inactive"

    def __getitem__(self, key):
        # Support getting instances by tag name as well as actual name
        try:
            return dict.__getitem__(self, key)
        except KeyError:
            for k, v in self.iteritems():
                try:
                    if v.tag == key and v.status != "Deleted":
                        return v
                except AttributeError:
                    pass
            raise KeyError(key)


class ServicesDirector(ProductInstance):
    """
    Represents a Services Director instance.
    """

    config_classes = {
        "Cluster": {
            "class": ConfigObjectFactory(
                "Cluster",
                [],
                ServicesDirectorConfigObject,
                {
                    "_is_deletable": False,
                    "_is_activatable": False
                }
            ),
            "path": "cluster", "name": "cluster",
            "plural": "s"
        },
        "FeaturePack": {
            "class": ConfigObjectFactory(
                "FeaturePack",
                ["stm_sku", "excluded"],
                ServicesDirectorConfigObject,
                {
                    "_is_deletable": False,
                    "_is_activatable": False
                }
            ),
            "path": "feature_pack", "name": "feature_pack",
            "plural": "s"
        },
        "Host": {
            "class": ConfigObjectFactory(
                "Host",
                ["work_location", "install_root", "username"],
                ServicesDirectorConfigObject,
                {
                    "_is_deletable": False,
                    "_is_activatable": False
                }
            ),
            "path": "host", "name": "host",
            "plural": "s"
        },
        "License": {
            "class": ConfigObjectFactory(
                "License",
                [],
                ServicesDirectorLicenseObject,
                {
                    "_is_deletable": False,
                    "_is_activatable": False
                }
            ),
            "path": "license", "name": "license",
            "plural": "s"
        },
        "ManagedInstance": {
            "class": ConfigObjectFactory(
                "ManagedInstance",
                ["owner", "management_address", "host_name", "stm_version",
                "admin_password", "bandwidth", "license_name", "cpu_usage",
                "stm_feature_pack", "container_configuration"],
                ServicesDirectorManagedInstanceObject,
                {
                    "_is_deletable": False
                }
            ),
            "path": "instance", "name": "managed_instance",
            "plural": "s"
        },
        "Manager": {
            "class": ConfigObjectFactory(
                "Manager",
                [],
                ServicesDirectorConfigObject,
                {}
            ),
            "path": "manager", "name": "manager",
            "plural": "s"
        },
        "SKU": {
            "class": ConfigObjectFactory(
                "SKU",
                [],
                ServicesDirectorConfigObject,
                {
                    "_is_read_only": True
                }
            ),
            "path": "sku", "name": "sku",
            "plural": "s"
        },
        "UnmanagedInstance": {
            "class": ConfigObjectFactory(
                "UnmanagedInstance",
                ["owner", "management_address", "stm_feature_pack",
                "admin_username", "admin_password", "bandwidth"],
                ServicesDirectorUnmanagedInstanceObject,
                {
                    "_url_modifiers": {
                        "PUT": {
                            "type": "querystring", "value": "managed=false"
                        }
                    }
                }
            ),
            "path": "instance", "name": "unmanaged_instance",
            "plural": "s"
        },
        "User": {
            "class": ConfigObjectFactory(
                "User",
                ["password"],
                ServicesDirectorUserObject,
                {
                    "_alternate_deactivate": True,
                    "_is_activatable": False
                }
            ),
            "path": "user", "name": "user",
            "plural": "s"
        },
        "Version": {
            "class": ConfigObjectFactory(
                "Version",
                ["version_filename"],
                ServicesDirectorConfigObject,
                {
                    "_is_deletable": False,
                    "_is_activatable": False
                }
            ),
            "path": "version", "name": "version",
            "plural": "s"
        }
    }

    def __init__(self, base_url, username, password, initialize_config=False,
                 connectivity_test_url=None):
        super(ServicesDirector, self).__init__(
            base_url, username, password, ServicesDirectorConfigObjectList,
            initialize_config, connectivity_test_url
        )
