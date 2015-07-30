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

from keystoneclient.v3 import client as keystone_client
from neutronclient.neutron import client as neutron_client
from oslo.config import cfg


class OpenStackInterface(object):
    def __init__(self):
        self.admin_username = cfg.CONF.lbaas_settings.openstack_username
        self.admin_password = cfg.CONF.lbaas_settings.openstack_password
        # Get Neutron API endpoint...
        keystone = self.get_keystone_client()
        neutron_service = keystone.services.find(name="neutron")
        self.neutron_endpoint = keystone.endpoints.find(
            interface="admin", service_id=neutron_service.id
        ).url

    def add_ip_to_ports(self, ip, ports):
        """
        Adds IP address to the allowed_address_pairs field of ports.
        """
        neutron = self.get_neutron_client()
        # Loop through all the ports, typically one per vTM cluster member
        for port_id in ports:
            port = neutron.show_port(port_id)['port']
            port_ips = [
                addr['ip_address'] for addr in port['allowed_address_pairs']
            ]
            # Add the IP if it isn't already in allowed_address_pairs
            if ip not in port_ips:
                port_ips.append(ip)
                allowed_pairs = []
                for addr in port_ips:
                    allowed_pairs.append({"ip_address": addr})
                neutron.update_port(
                    port_id, {"port": {
                        "allowed_address_pairs": allowed_pairs
                    }}
                )

    def delete_ip_from_ports(self, ip, ports):
        """
        Deletes IP address from the allowed_address_pairs field of ports.
        """
        neutron = self.get_neutron_client()
        # Loop through all the ports, typically one per vTM cluster member
        for port_id in ports:
            port = neutron.show_port(port_id)['port']
            port_ips = [
                addr['ip_address'] for addr in port['allowed_address_pairs']
            ]
            # Delete the IP if it is in allowed_address_pairs
            if ip in port_ips:
                new_pairs = []
                for port_ip in port_ips:
                    if ip != port_ip:
                        new_pairs.append({"ip_address": port_ip})
                neutron.update_port(
                    port_id, {"port": {"allowed_address_pairs": new_pairs}}
                )

    def get_neutron_client(self):
        auth_token = self.get_auth_token()
        neutron = neutron_client.Client(
            '2.0', endpoint_url=self.neutron_endpoint, token=auth_token
        )
        neutron.format = 'json'
        return neutron

    def get_keystone_client(self, tenant_id=None, tenant_name=None):
        keystone_url = "%s://%s:%s/v3" % (
            cfg.CONF.keystone_authtoken.auth_protocol,
            cfg.CONF.keystone_authtoken.auth_host,
            cfg.CONF.keystone_authtoken.auth_port
        )
        params = {
            "username": self.admin_username,
            "password": self.admin_password,
            "auth_url": keystone_url
        }
        if tenant_id:
            params['tenant_id'] = tenant_id
        elif tenant_name:
            params['tenant_name'] = tenant_name
        else:
            params['tenant_name'] = "admin"
        keystone = keystone_client.Client(**params)
        return keystone

    def get_auth_token(self, tenant_id=None, tenant_name=None):
        keystone_client = self.get_keystone_client(tenant_id, tenant_name)
        return keystone_client.auth_token

