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
                             ConfigObjectFactory, TextOnlyObjectFactory,\
                             ProductInstance
import json

from oslo_log import log as logging

LOG = logging.getLogger(__name__)
###############################################################################
#                           Abstract config object classes                    #
###############################################################################



class vTMConfigObject(ConfigObject):

    def create_from_config_data(self, data):
        protected = ['update', 'delete']
        try:
            data = json.loads(data)
        except TypeError:
            pass
        for section in data['properties']:
            if section == "basic":
                for field, value in data['properties'][section].iteritems():
                    if field not in protected:
                        setattr(self, field, value)
            else:
                for field, value in data['properties'][section].iteritems():
                    setattr(self, "%s__%s" % (section, field), value)

    def to_dict(self, ignore_properties=None):
        obj_dict = {"properties": {"basic": {}}}
        properties = vars(self).copy()
        ignore = ['name', '_object_type', 'connector', '_parent_list']
        if ignore_properties:
            ignore += ignore_properties
        for p in ignore:
            try:
                del properties[p]
            except KeyError:
                pass
        for field, value in properties.iteritems():
            if isinstance(value, SubList):
                tmp_list = []
                for item in value:
                    n = value.get(item)
                    tmp_list.append(n.to_dict())
                value = tmp_list
            if field.startswith("_"):
                field = field[1:]
            try:
                section, field_name = field.split("__")
                if section not in obj_dict['properties']:
                    obj_dict['properties'][section] = {}
                obj_dict['properties'][section][field_name] = value
            except ValueError:
                obj_dict['properties']['basic'][field] = value
        return obj_dict


###############################################################################
#                               Object 'list' classes                         #
###############################################################################

class vTMConfigObjectList(ConfigObjectList):
    """
    Dictionary of top-level configuration objects.

    Maps object name to configuration object and provides methods for
    manupulating the dictionary.
    """

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
        new_object = super(vTMConfigObjectList, self).create(
            name, *args, **kwargs
        )
        return new_object

    def update(self, name, *args, **kwargs):
        return self.create(name, *args, **kwargs)


###############################################################################
#                         Non-standard config object classes                  #
###############################################################################

class Statistics(object):
    sections = ["globals", "virtual_servers", "pools", "listen_ips"]

    def __init__(self, stats_url, connector):
        for section in self.sections:
            setattr(self, section, self.Section(stats_url, section, connector))

    class Section(dict):

        class NoCountersReturnedError(Exception):
            pass

        class NoDataAvailableError(Exception):
            pass

        def __init__(self, stats_url, section, connector):
            self.stats_url = stats_url
            self.section = section
            self.connector = connector

        class ConfigItem(dict):
            def __getattr__(self, name):
                return self[name]

        def __getitem__(self, name):
            response = self.connector.get(
                "{}/{}".format(self.stats_url, self.section)
            )
            if name not in [obj['name'] for obj in response.json()['children']]:
                raise self.NoDataAvailableError()
            response = self.connector.get("%s/%s/%s" % (
                self.stats_url, self.section, name
            ))
            if (response.status_code == 400
            and response.json()['error_id'] == "statistics.no_counters"):
                raise self.NoCountersReturnedError()
            return self.ConfigItem(response.json()['statistics'])

        def __getattr__(self, name):
            response = self.connector.get("%s/%s" % (
                self.stats_url, self.section
            ))
            if 200 <= response.status_code < 300:
                stats = response.json()
                try:
                    return stats['statistics'][name]
                except KeyError:
                    raise AttributeError(name)
            else:
                raise Exception("Failed to get stats from vTM")


class Node(vTMConfigObject):
    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        if value not in ["active", "disabled", "draining"]:
            raise Exception("Invalid node state '%s'" % value)
        self._state = value

    def __init__(self, name, ip, port, state="active", weight=1, priority=1):
        self.ip = ip
        self.port = port
        self.state = state
        self.weight = weight
        self.priority = priority

    def to_dict(self):
        return {
            "node": "%s:%s" % (self.ip, self.port),
            "priority": self.priority,
            "weight": self.weight,
            "state": self.state
        }

    def update(self):
        self.parent.connector("PUT", str(self.parent))


class Pool(vTMConfigObject):

    def __init__(self, name, config=None, nodes=None, **kwargs):
        if config is not None:
            super(Pool, self).__init__(name, "Pool")
            self.create_from_config_data(config)
        elif nodes:
            super(Pool, self).__init__(name, "Pool", **kwargs)
            self.nodes_table = nodes
        else:
            raise Exception("Invalid parameters specified")

    def create_from_config_data(self, data):
        super(Pool, self).create_from_config_data(data)
        nodes_table = self.nodes_table
        self.nodes_table = SubList(Node, self)
        for node in nodes_table:
            try:
                self.nodes_table.instantiate(
                    node['node'],
                    ip=node['node'].split(":")[0],
                    port=node['node'].split(":")[1],
                    state=node['state'],
                    weight=node['weight'],
                    priority=node['priority']
                )
            except KeyError:
                self.nodes_table.instantiate(
                    node['node'],
                    ip=node['node'].split(":")[0],
                    port=node['node'].split(":")[1],
                    state=node['state'],
                    weight=node['weight'] or 1
                )
        self.nodes = self.nodes_table

    def to_dict(self):
        return super(Pool, self).to_dict(["nodes"])


class CustomData(vTMConfigObject):
    def __init__(self, name, config=None, **kwargs):
        super(CustomData, self).__init__(name, "CustomData")
        if config:
            for item in config['properties']['basic']['string_lists']:
                setattr(self, item['name'], item['value'])
        else:
            for field, value in kwargs.iteritems():
                setattr(self, field, str(value))

    def delete(self, attr_name=None):
        if attr_name is not None:
            delattr(self, attr_name)
        else:
            super(CustomData, self).delete()

    def to_dict(self):
        obj_dict = {"properties": {"basic": {}}}
        val_list = []
        obj_vars = vars(self).copy()
        for ignore_me in ["name", "_object_type", "connector", "_parent_list"]:
            try:
                del obj_vars[ignore_me]
            except KeyError:
                pass
        for key in obj_vars:
            value = getattr(self, key)
            if not isinstance(value, list):
                value = [value]
            val_list.append(
                {
                    "name": key,
                    "value": value
                }
            )
        obj_dict['properties']['basic']['string_lists'] = val_list
        return obj_dict


GlobalSettings = ConfigObjectFactory(
    "GlobalSettings", [], vTMConfigObject
)

SecuritySettings = ConfigObjectFactory(
    "SecuritySettings", [], vTMConfigObject
)


class vTM(ProductInstance):
    """
    Represents a single vTM instance.
    """

    config_classes = {
        "ActionProgram": {
            "class": TextOnlyObjectFactory(
                "ActionProgram", "program_text"
            ),
            "path": "action_programs", "name": "action_program",
            "plural": "s"},
        "AlertAction": {
            "class": ConfigObjectFactory(
                "AlertAction",
                ["type"],
                vTMConfigObject
            ),
            "path": "actions", "name": "alert_action", "plural": "s"},
        "BandwidthClass": {
            "class": ConfigObjectFactory(
                "BandwidthClass",
                ["maximum"],
                vTMConfigObject
            ),
            "path": "bandwidth", "name": "bandwidth_class", "plural": "es"},
        "CloudCredentials": {
            "class": ConfigObjectFactory(
                "CloudCredentials",
                [],
                vTMConfigObject
            ),
            "path": "cloud_api_credentials", "name": "cloud_cred",
            "plural": "s"},
        "CustomData": {
            "class": CustomData,
            "path": "custom", "name": "custom_data", "plural": ""},
        "EventType": {
            "class": ConfigObjectFactory(
                "EventType",
                ["actions"],
                vTMConfigObject
            ),
            "path": "event_types", "name": "event_type", "plural": "s"},
        "ExtraFile": {
            "class": TextOnlyObjectFactory(
                 "ExtraFile",
                 "file_text"
            ),
            "path": "extra_files", "name": "extra_file", "plural": "s"},
        "GLBService": {
            "class": ConfigObjectFactory(
                "GLBService",
                [],
                vTMConfigObject
            ),
            "path": "glb_services", "name": "glb_service", "plural": "s"},
        "HealthMonitor": {
            "class": ConfigObjectFactory(
                "HealthMonitor",
                ["type"],
                vTMConfigObject
            ),
            "path": "monitors", "name": "monitor", "plural": "s"},
        "LicenseKey": {
            "class": TextOnlyObjectFactory(
                "LicenseKey",
                "key_text"
            ),
            "path": "license_keys", "name": "license_key", "plural": "s"},
        "Location": {
            "class": TextOnlyObjectFactory(
                "Location",
                ["type"]
            ),
            "path": "locations", "name": "location", "plural": "s"},
        "MonitorScript": {
            "class": TextOnlyObjectFactory(
                "MonitorScript",
                "script_text"
            ),
            "path": "monitor_scripts", "name": "monitor_script",
            "plural": "s"},
        "PersistenceClass": {
            "class": ConfigObjectFactory(
                "PersistenceClass",
                ["type"],
                vTMConfigObject
            ),
            "path": "persistence", "name": "persistence_class",
            "plural": "es"},
        "ProtectionClass": {
            "class": ConfigObjectFactory(
                "ProtectionClass",
                [],
                vTMConfigObject
            ),
            "path": "protection", "name": "protection_class",
            "plural": "es"},
        "Pool": {
            "class": Pool,
            "path": "pools", "name": "pool", "plural": "s"},
        "RateClass": {
            "class": ConfigObjectFactory(
                "RateClass",
                [],
                vTMConfigObject
            ),
            "path": "rate", "name": "rate_class", "plural": "es"},
        "Rule": {
            "class": TextOnlyObjectFactory(
                "Rule",
                "rule_text"
            ),
            "path": "rules", "name": "rule", "plural": "s"},
        "ServiceLevelMonitor": {
            "class": ConfigObjectFactory(
                "ServiceLevelMonitor",
                ["response_time"],
                vTMConfigObject
            ),
            "path": "service_level_monitors", "name": "slm_class",
            "plural": "es"},
        "SSLClientCert": {
            "class": ConfigObjectFactory(
                "SSLClientCert",
                ["public", "private"],
                vTMConfigObject
            ),
            "path": "ssl/client_keys", "name": "ssl_client_key",
            "plural": "s"},
        "SSLServerCert": {
            "class": ConfigObjectFactory(
                "SSLServerCert",
                ["public", "private"],
                vTMConfigObject
            ),
            "path": "ssl/server_keys", "name": "ssl_server_cert",
            "plural": "s"},
        "SSLTrustedCert": {
            "class": TextOnlyObjectFactory(
                "SSLTrustedCert",
                "cert_text"
            ),
            "path": "ssl/cas", "name": "ssl_trusted_cert",
            "plural": "s"},
        "TrafficIPGroup": {
            "class": ConfigObjectFactory(
                "TrafficIPGroup",
                ["ipaddresses"],
                vTMConfigObject
            ),
            "path": "traffic_ip_groups", "name": "tip_group", "plural": "s"},
        "TrafficManager": {
            "class": ConfigObjectFactory(
                "TrafficManager",
                [],
                vTMConfigObject
            ),
            "path": "traffic_managers", "name": "traffic_manager",
            "plural": "s"},
        "TrafficScriptAuthenticator": {
            "class": ConfigObjectFactory(
                "TrafficScriptAuthenticator",
                [],
                vTMConfigObject
            ),
            "path": "rule_authenticators", "name": "ts_authenticator",
            "plural": "s"},
        "UserAuthenticator": {
            "class": ConfigObjectFactory(
                "UserAuthenticator",
                ["type"],
                vTMConfigObject
            ),
            "path": "user_authenticators", "name": "user_authenticator",
            "plural": "s"},
        "UserGroup": {
            "class": ConfigObjectFactory(
                "UserGroup",
                ["permissions"],
                vTMConfigObject
            ),
            "path": "user_groups", "name": "user_group", "plural": "s"},
        "VirtualServer": {
            "class": ConfigObjectFactory(
                "VirtualServer",
                ["enabled", "protocol", "port", "pool"],
                vTMConfigObject
            ),
            "path": "virtual_servers", "name": "vserver", "plural": "s"}
    }

    def __init__(self, base_url, username, password, initialize_config=False,
                 connectivity_test_url=None):
        url = "%s/config/active" % base_url
        self.uuid_test_url = "{}/status/local_tm/information".format(
            base_url
        )
        super(vTM, self).__init__(
            url, username, password, vTMConfigObjectList,
            initialize_config, connectivity_test_url
        )
        #   Statistics
        # TODO: have object-specific stats available through the object itself
        self.stats_url = "%s/status/local_tm/statistics" % base_url
        self.statistics = Statistics(self.stats_url, self.http_session)
        # Initialize config object that only exist as single entities:
        global_conn = self.get_object_connector(
            GlobalSettings, "global_settings"
        )
        security_conn = self.get_object_connector(SecuritySettings, "security")
        if initialize_config:
            self.global_settings = GlobalSettings(
                "GlobalSettings", config=global_conn()
            )
            self.security = SecuritySettings(
                "SecuritySettings", config=security_conn()
            )
        else:
            self.global_settings = GlobalSettings("GlobalSettings")
            self.security = SecuritySettings("SecuritySettings")
        self.global_settings.connector = global_conn
        self.security.connector = security_conn

    def test_uuid_set(self):
        try:
            response = self.http_session.get(
                self.uuid_test_url, timeout=3
            )
        except Exception as e:
            return False
        if response.status_code == 200:
            if response.json()['information']['uuid']:
                return True
        return False

    def get_nodes_in_cluster(self):
        response = self.http_session.get("%s/traffic_managers" % (
            self.instance_url
        ))
        return [tm['name'] for tm in response.json()['children']]
