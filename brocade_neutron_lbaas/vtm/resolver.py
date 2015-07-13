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

import json
from openstack_connector import OpenStackInterface
from oslo.config import cfg
import requests

designate_settings = [
    cfg.StrOpt('endpoint',
               help=_('Designate REST endpoint host:port')),
    cfg.StrOpt('zone',
               help=_('Designate ID of the zone in which to create records'))
]
cfg.CONF.register_opts(designate_settings, "lbaas_designate_settings")


class Resolver(object):
    def __init__(self, method):
        try:
            plugin_name = "%sResolver" % method.capitalize()
            self.plugin = globals()[plugin_name]()
        except KeyError:
            raise Exception(
                _("Unsupported name resolution method '%s'" % method)
            )

    def __getattr__(self, name):
        def child_function_wrapper(*args):
            if hasattr(self.plugin, name):
                child_function = getattr(self.plugin, name)
                return child_function(*args)
            else:
                raise AttributeError(name)
        return child_function_wrapper


class NoopResolver(object):
    def add_record(self, hostname, ip):
        pass

    def delete_record(hostname):
        pass


class HostsResolver(object):
    def add_record(self, hostname, ip):
        """
        Adds record to the /etc/hosts file.
        """
        with open("/etc/hosts", "a") as hosts_file:
            hosts_file.write("%s %s\n" % (ip, hostname))

    def delete_record(self, hostname):
        """
        Deletes a record from the /etc/hosts file.
        """
        with open("/etc/hosts", "r") as hosts_file:
            entries = hosts_file.readlines()
        for entry in entries[:]:
            try:
                (ip, host) = entry.split()
                if host == hostname:
                    entries.remove(entry)
                    break
            except ValueError:
                pass  # Not a line added by this driver
        with open("/etc/hosts", "w") as hosts_file:
            hosts_file.write("".join(entries))


class DesignateResolver(object):
    """
    This was written from the Designate API v2 documentation but
    *** HAS NOT BEEN TESTED ***
    """
    def add_record(self, hostname, ip):
        openstack_connector = OpenStackInterface()
        auth_token = openstack_connector.get_auth_token()
        url = "%s/v2/zones/%s/recordsets" % (
            cfg.CONF.lbaas_designate_settings.endpoint,
            cfg.CONF.lbaas_designate_settings.zone
        )
        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Auth_token": auth_token
            },
            data=json.dumps({
                "recordset": {
                    "name": hostname,
                    "type": "A",
                    "ttl": 3600,
                    "records": [{"address": ip}]
                }
            })
        )
        if response.status_code != 201:
            raise Exception(_(
                "Failed to create Designate entry for host %s: %s" % (
                    hostname, response.text)
            ))

    def delete_record(self, hostname):
        openstack_connector = OpenStackInterface()
        auth_token = openstack_connector.get_auth_token()
        url = "%s/v2/zones/%s/recordsets?name=%s" % (
            cfg.CONF.lbaas_designate_settings.endpoint,
            cfg.CONF.lbaas_designate_settings.zone,
            hostname
        )
        response = requests.get(
            url,
            headers={
                "X-Auth-Token": auth_token,
                "Accept": "application/json"
            }
        )
        if response.status_code != 200:
            raise Exception(_(
                "Failed to locate Designate recordset for hostname %s" % (
                    hostname)
            ))
        recordset_id = response.json()['recordsets'][0]['id']
        url = "%s/v2/zones/%s/recordsets/%s" % (
            cfg.CONF.lbaas_designate_settings.endpoint,
            cfg.CONF.lbaas_designate_settings.zone,
            recordset_id
        )
        response = requests.delete(url, headers={"X-Auth-Token": auth_token})
        if response.status_code != 204:
            raise Exception(_(
                "Failed to delete Designate entry for host %s: %s" % (
                    hostname, response.text)
            ))
