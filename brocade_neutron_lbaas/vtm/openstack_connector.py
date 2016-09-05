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

import base64
import json
from neutronclient.neutron import client as neutron_client
from oslo_log import log as logging
from oslo.config import cfg
import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import socket
import struct
from time import sleep

LOG = logging.getLogger(__name__)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class OpenStackInterface(object):
    def __init__(self):
        self.admin_password = cfg.CONF.lbaas_settings.os_admin_password
        self.admin_project_id = cfg.CONF.lbaas_settings.os_admin_project_id
        self.admin_username = cfg.CONF.lbaas_settings.os_admin_username
        self.lbaas_password = cfg.CONF.lbaas_settings.lbaas_project_password
        self.lbaas_project_id = cfg.CONF.lbaas_settings.lbaas_project_id
        self.lbaas_username = cfg.CONF.lbaas_settings.lbaas_project_username
        # Get Neutron and Nova API endpoints...
        keystone = self.get_keystone_client(lbaas_tenant=True)
        neutron_service = keystone.services.find(name="neutron")
        nova_service = keystone.services.find(name="nova")
        if cfg.CONF.lbaas_settings.keystone_version == "2":
            self.neutron_endpoint = keystone.endpoints.find(
                service_id=neutron_service.id
            ).adminurl
            nova_endpoint = keystone.endpoints.find(
                service_id=nova_service.id
            ).adminurl
            # Different versions appear to use different placeholders...
            self.nova_endpoint = nova_endpoint.replace(
                "$(tenant_id)s", self.lbaas_project_id
            )
            self.nova_endpoint = self.nova_endpoint.replace(
                "%(tenant_id)s", self.lbaas_project_id
            )
        else:
            self.neutron_endpoint = keystone.endpoints.find(
                interface="admin", service_id=neutron_service.id
            ).url
            nova_endpoint = keystone.endpoints.find(
                interface="admin", service_id=nova_service.id
            ).url
            self.nova_endpoint = nova_endpoint.replace(
                "%(tenant_id)s", self.lbaas_project_id
            )

    def create_vtm(self, hostname, lb, password, ports, cluster=None,
                   avoid=None):
        """
        Creates a vTM instance as a Nova VM.
        """
        user_data = self._generate_user_data(
            hostname, password, ports['data'], ports['mgmt'], cluster
        )
        nics = [{"port": ports['data']['id']}]
        if ports['mgmt'] is not None:
            nics.insert(0, {"port": ports['mgmt']['id']})
        instance = self.create_server(
            hostname=hostname,
            user_data=self._generate_cloud_init_file(user_data),
            nics=nics,
            password=password,
            avoid_host_of=avoid
        )
        self.set_server_lock(instance['id'], lock=True)
        self._await_build_complete(instance['id'])
        return instance

    def destroy_vtm(self, hostname, lb):
        port_list = []
        sec_grp_list = []
        floatingip_list = []
        server_id = self.get_server_id_from_hostname(hostname)
        neutron = self.get_neutron_client()
        # Build lists of ports, floating IPs and security groups to delete
        ports = neutron.list_ports(device_id=server_id)
        for port in ports['ports']:
            port_list.append(port['id'])
            sec_grp_list += port['security_groups']
            floatingip_list += [
                floatingip['id']
                for floatingip in neutron.list_floatingips(
                    port_id=port['id']
                )['floatingips']
            ]
        # Delete the instance
        self.delete_server(server_id)
        # Delete floating IPs
        for flip in floatingip_list:
            try:
                neutron.delete_floatingip(flip)
            except Exception as e:
                LOG.error(_("\nError deleting floating IP %s: %s" % (flip, e)))
        # Delete ports
        for port in port_list:
            if port != lb.vip_port_id:
                # Port isn't bound to the LBaaS "loadbalancer" object so
                # just delete it.
                neutron.delete_port(port)
            else:
                # Port can't be deleted as it's still bound to the LBaaS
                # "loadbalancer" object. Therefore just set the security
                # group to nothing so it too isn't bound, and can be deleted.
                neutron.update_port(
                    port,
                    {"port": {"security_groups": []}}
                )
        # Delete security groups
        for sec_grp in sec_grp_list:
            try:
                neutron.delete_security_group(sec_grp)
            except Exception:
                # Might legitimately fail in HA deployments
                pass

    def clean_up(self, ports=None, security_groups=None, instances=None,
                 floating_ips=None):
        if instances is not None:
            for instance in instances:
                self.delete_server(instance)
        neutron = self.get_neutron_client()
        if floating_ips is not None:
            for flip in floating_ips:
                neutron.delete_floatingip(flip)
        if ports is not None:
            for port in ports:
                neutron.delete_port(port)
        if security_groups is not None:
            for sec_grp in security_groups:
                neutron.delete_security_group(sec_grp)

    def vtm_exists(self, hostname):
        """
        Tests whether a vTM instance with the specified hosname exists.
        """
        hostname = hostname[0] if isinstance(hostname, tuple) else hostname
        try:
            self.get_server_id_from_hostname(hostname)
            return True
        except:
            return False

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

    def _await_build_complete(self, instance_id):
        """
        Waits for a Nova instance to be built.
        """
        instance = self.get_server(instance_id)
        status = instance['status']
        while status == 'BUILD':
            sleep(10)
            instance = self.get_server(instance_id)
            status = instance['status']
            if status == 'ERROR':
                self.delete_server(instance_id)
                raise Exception("VM build failed")

    def create_port(self, lb, hostname, mgmt_port=False, cluster=False,
                    create_floating_ip=False, security_group=None,
                    identifier=None):
        if identifier is None and security_group is None:
            raise Exception("Must specify either security_group or identifier")
        neutron = self.get_neutron_client()
        if mgmt_port is False:
            subnet = neutron.show_subnet(lb.vip_subnet_id)
            network_id = subnet['subnet']['network_id']
        else:
            network_id = cfg.CONF.lbaas_settings.management_network
        port_config = {"port": {
            "admin_state_up": True,
            "network_id": network_id,
            "tenant_id": self.lbaas_project_id,
            "name": "%s-%s" % ("mgmt" if mgmt_port else "data", hostname)
        }}
        if mgmt_port is False:
            port_config['port']['fixed_ips'] = [
                {'subnet_id': lb.vip_subnet_id}
            ]
        port = neutron.create_port(port_config)['port']

        if create_floating_ip is True:
            floatingip = self.create_floatingip(port['id'])
            mgmt_ip = floatingip['floatingip']['floating_ip_address']
            if security_group is None:
                sec_grp = self.create_lb_security_group(
                    lb.tenant_id, identifier, mgmt_port=True, cluster=cluster
                )
                security_group = sec_grp['security_group']['id']
        else:
            if security_group is None:
                if mgmt_port is False:
                    sec_grp = self.create_lb_security_group(
                        lb.tenant_id, identifier
                    )
                else:
                    sec_grp = self.create_lb_security_group(
                        lb.tenant_id, identifier, mgmt_port=True,
                        mgmt_label=True, cluster=cluster
                    )
                security_group = sec_grp['security_group']['id']            
            if mgmt_port is False:
                mgmt_ip = None
            else:
                mgmt_ip = port['fixed_ips'][0]['ip_address']
        neutron.update_port(
            port['id'],
            {"port": {
                "security_groups": [security_group]
            }}
        )
        return(port, security_group, mgmt_ip)

    def vtm_has_subnet_port(self, hostname, lb):
        hostname = hostname[0] if isinstance(hostname, tuple) else hostname
        ports = self.get_server_ports(hostname)
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                if fixed_ip['subnet_id'] == lb.vip_subnet_id:
                    return True
        return False

    def subnet_in_use(self, lb):
        neutron = self.get_neutron_client()
        loadbalancers = neutron.list_loadbalancers(
            tenant_id=lb.tenant_id,
            vip_subnet_id=lb.vip_subnet_id
        )['loadbalancers']
        if len(loadbalancers) > 1:
            return True
        return False

    def attach_port(self, hostname, lb, identifier):
        server_id = self.get_server_id_from_hostname(hostname)
        sec_grp_id = self.get_security_group_id(
            "lbaas-{}".format(identifier)
        )
        port, junk, junk = self.create_port(
            lb, hostname, security_group=sec_grp_id
        )
        self.attach_port_to_instance(server_id, port['id'])
        return port

    def detach_port(self, hostname, lb):
        neutron = self.get_neutron_client()
        server_id = self.get_server_id_from_hostname(hostname)
        ports = neutron.list_ports(device_id=server_id,)['ports']
        for port in ports:
            if port['fixed_ips'][0]['subnet_id'] == lb.vip_subnet_id:
                self.detach_port_from_instance(server_id, port['id'])
                neutron.delete_port(port['id'])
                return port['fixed_ips'][0]['ip_address']
        raise Exception(_(
            "No port found for subnet {} on device {}".format(
                lb.vip_subnet_id, hostname)
        ))

    def get_security_group_id(self, sec_grp_name):
        neutron = self.get_neutron_client()
        sec_grps = neutron.list_security_groups(name=sec_grp_name)
        try:
            return sec_grps['security_groups'][0]['id']
        except IndexError:
            raise Exception(
                _("Security group {} not found".format(sec_grp_name))
            )

    def create_lb_security_group(self, tenant_id, uuid, mgmt_port=False,
                                 mgmt_label=False, cluster=False):
        """
        Creates a security group.
        """
        neutron = self.get_neutron_client()
        sec_grp_data = {"security_group": {
            "name": "%slbaas-%s" % ("mgmt-" if mgmt_label else "", uuid),
            "tenant_id": self.lbaas_project_id
        }}
        sec_grp = neutron.create_security_group(sec_grp_data)
        # Add egress rules (CM override the defaults, making them unusable)
        self.create_security_group_rule(
            tenant_id,
            sec_grp['security_group']['id'],
            port=None,
            direction="egress",
            protocol=None
        )
       
        # If GUI access is allowed, open up the GUI port
        if cfg.CONF.vtm_settings.gui_access is True and mgmt_label:
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port
            )
        # If mgmt_port, add the necessary rules to allow management traffic
        if mgmt_port:
            # REST access
            for server in cfg.CONF.lbaas_settings.configuration_source_ips:
                self.create_security_group_rule(
                    tenant_id,
                    sec_grp['security_group']['id'],
                    port=cfg.CONF.vtm_settings.rest_port,
                    src_addr=socket.gethostbyname(server)
                )
            # SNMP access
            for cidr in cfg.CONF.vtm_settings.snmp_allow_from:
                self.create_security_group_rule(
                    tenant_id,
                    sec_grp['security_group']['id'],
                    port=161,
                    protocol='udp',
                    src_addr=cidr
                )
        # If cluster, add necessary ports for intra-cluster comms
        if cluster is True:
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port,
                remote_group=sec_grp['security_group']['id']
            )
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port,
                remote_group=sec_grp['security_group']['id'],
                protocol='udp'
            )
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.cluster_port,
                remote_group=sec_grp['security_group']['id']
            )
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.cluster_port,
                remote_group=sec_grp['security_group']['id'],
                protocol='udp'
            )
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.rest_port,
                remote_group=sec_grp['security_group']['id']
            )
        return sec_grp

    def create_security_group_rule(self, tenant_id, sec_grp_id, port,
                                   src_addr=None, remote_group=None,
                                   direction="ingress", protocol='tcp'):
        """
        Creates the designatted rule in a security group.
        """
        if isinstance(port, tuple):
            port_min = port[0]
            port_max = port[1]
        else:
            port_min = port
            port_max = port
        neutron = self.get_neutron_client()
        new_rule = {"security_group_rule": {
            "direction": direction,
            "port_range_min": port_min,
            "ethertype": "IPv4",
            "port_range_max": port_max,
            "protocol": protocol,
            "security_group_id": sec_grp_id,
            "tenant_id": self.lbaas_project_id
        }}
        if src_addr:
            new_rule['security_group_rule']['remote_ip_prefix'] = src_addr
        if remote_group:
            new_rule['security_group_rule']['remote_group_id'] = remote_group
        try:
            neutron.create_security_group_rule(new_rule)
        except Exception as e:
            # Rule may already exist
            pass

    def allow_port(self, lb, port, identifier, protocol='tcp'):
        """
        Adds access to a given port to a security group.
        """
        # Get the name of the security group for the "loadbalancer"
        sec_grp_name = "lbaas-%s" % identifier
        # Get the security group
        neutron = self.get_neutron_client()
        sec_grp = neutron.list_security_groups(
            name=sec_grp_name
        )['security_groups'][0]
        # Create the required rule
        self.create_security_group_rule(
            lb.tenant_id, sec_grp['id'], port, protocol=protocol
        )

    def block_port(self, lb, port, identifier, protocol='tcp'):
        """
        Removes access to a given port from a security group.
        """
        # Get the name of the security group for the "loadbalancer"
        sec_grp_name = "lbaas-%s" % identifier
        # Get the security group
        neutron = self.get_neutron_client()
        sec_grp = neutron.list_security_groups(
            name=sec_grp_name
        )['security_groups'][0]
        # Iterate through all rules in the group and delete the matching one
        for rule in sec_grp['security_group_rules']:
            if rule['port_range_min'] == port \
                and rule['port_range_max'] == port \
                and rule['direction'] == "ingress" \
                and rule['protocol'] == protocol:
                neutron.delete_security_group_rule(rule['id'])
                break

    def create_floatingip(self, port_id):
        neutron = self.get_neutron_client()
        network = cfg.CONF.lbaas_settings.management_network
        floatingip_data = {"floatingip": {
            "floating_network_id": network,
            "port_id": port_id,
            "tenant_id": self.lbaas_project_id
        }}
        return neutron.create_floatingip(floatingip_data)

    def get_network_for_subnet(self, subnet_id):
        neutron = self.get_neutron_client()
        return neutron.show_subnet(subnet_id)['subnet']['network_id']

    def create_server(self, hostname, user_data, nics, password,
                      avoid_host_of=None):
        """
        Creates a Nova instance of the vTM image.
        """
        token = self.get_auth_token()
        headers = {
            "Content-Type": "application/json",
            "X-Auth-Token": token
        }
        body = {"server": {
            "imageRef": cfg.CONF.lbaas_settings.image_id,
            "flavorRef": cfg.CONF.lbaas_settings.flavor_id,
            "name": hostname,
            "user_data": base64.b64encode(user_data),
            "adminPass": password,
            "networks": nics,
            "config_drive": True
        }}
        if cfg.CONF.lbaas_settings.availability_zone is not None:
            body['server']['availability_zone'] = \
                cfg.CONF.lbaas_settings.availability_zone
        if avoid_host_of is not None:
            body['os:scheduler_hints'] = {
                "different_host": [avoid_host_of]
            }
        try:
            response = requests.post(
                "%s/servers" % self.nova_endpoint,
                data=json.dumps(body),
                headers=headers
            )
            if response.status_code >= 300:
                raise Exception("%s: %s" % (
                    response.status_code, response.text
                ))
        except Exception as e:
            raise Exception(_("\nError creating vTM instance: %s" % e))
        return response.json()['server']

    def get_server(self, server_id):
        token = self.get_auth_token()
        response = requests.get(
            "%s/servers/%s" % (self.nova_endpoint, server_id),
            headers={"X-Auth-Token": token}
        )
        if response.status_code != 200:
            raise Exception("Server Not found")
        return response.json()['server']

    def attach_port_to_instance(self, server_id, port_id):
        token = self.get_auth_token()
        response = requests.post(
            "%s/servers/%s/os-interface" % (self.nova_endpoint, server_id),
            data=json.dumps({"interfaceAttachment": { "port_id": port_id}}),
            headers={"X-Auth-Token": token, "Content-Type": "application/json"}
        )
        if response.status_code != 200:
            raise Exception(
                "Unable to attach port '{}' to instance '{}': {}".format(
                    port_id, server_id, response.text
            ))

    def detach_port_from_instance(self, server_id, port_id):
        token = self.get_auth_token()
        response = requests.delete(
            "%s/servers/%s/os-interface/%s" % (
                self.nova_endpoint, server_id, port_id
            ),
            headers={"X-Auth-Token": token}
        )
        if response.status_code != 202:
            raise Exception(
                "Unable to detach port '{}' from instance '{}': {}".format(
                    port_id, server_id, response.text
            ))

    def get_mgmt_ip(self, hostname):
        neutron = self.get_neutron_client()
        mgmt_net = neutron.show_network(
            cfg.CONF.lbaas_settings.management_network
        )['network']['name']
        server_id = self.get_server_id_from_hostname(hostname)
        server = self.get_server(server_id)
        return server['addresses'][mgmt_net][0]['addr']

    def set_server_lock(self, server_id, lock=True):
        token = self.get_auth_token()
        response = requests.post(
            "%s/servers/%s/action" % (self.nova_endpoint, server_id),
            headers={
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            },
            data='{ "%s": null }' % ("lock" if lock else "unlock")
        )
        if response.status_code != 202:
            raise Exception("Failed to lock server %s" % server_id)

    def get_server_ports(self, hostname):
        """
        Gets the Neutron ID of a vTM's data port.
        """
        neutron = self.get_neutron_client()
        server_id = self.get_server_id_from_hostname(hostname)
        all_ports = neutron.list_ports(device_id=server_id)['ports']
        data_ports = [
            port for port in all_ports
            if not port['name'].startswith("mgmt")
        ]
        if data_ports:
            return data_ports
        raise Exception("No data ports found for %s" % hostname)

    def get_server_port_ids(self, hostname):
        ports = self.get_server_ports(hostname)
        return [port['id'] for port in ports]

    def get_server_id_from_hostname(self, hostname):
        """
        Gets the Nova ID of a server from its hostname.
        """
        token = self.get_auth_token()
        response = requests.get(
            "%s/servers?name=%s" % (self.nova_endpoint, hostname),
            headers={"X-Auth-Token": token}
        )
        try:
            return response.json()['servers'][0]['id']
        except:
            raise Exception("Server not found")

    def delete_server(self, server_id):
        """
        Deletes a Nova instance.
        """
        self.set_server_lock(server_id, lock=False)
        token = self.get_auth_token()
        requests.delete(
            "%s/servers/%s" % (self.nova_endpoint, server_id),
            headers={"X-Auth-Token": token}
        )

    def get_subnet_gateway(self, subnet_id):
        neutron = self.get_neutron_client()
        subnet = neutron.show_subnet(subnet_id)['subnet']
        ports = neutron.list_ports(network_id=subnet['network_id'])['ports']
        for port in ports:
            for fixed_ip in port['fixed_ips']:
                if fixed_ip['ip_address'] == subnet['gateway_ip']:
                    return (subnet['gateway_ip'], port['mac_address'])
        return (None, None)

    def get_neutron_client(self):
        auth_token = self.get_auth_token(lbaas_tenant=False)
        neutron = neutron_client.Client(
            '2.0', endpoint_url=self.neutron_endpoint, token=auth_token
        )
        neutron.format = 'json'
        return neutron

    def get_keystone_client(self, lbaas_tenant=False):
        auth_url = re.match(
            "^(https?://[^/]+)",
            cfg.CONF.keystone_authtoken.auth_uri
        ).group(1)
        if cfg.CONF.lbaas_settings.keystone_version == "2":
            from keystoneclient.v2_0 import client as keystone_client
            auth_url = "%s/v2.0" % auth_url
        else:
            from keystoneclient.v3 import client as keystone_client
            auth_url = "%s/v3" % auth_url

        if lbaas_tenant:
            password = self.lbaas_password
            project_id = self.lbaas_project_id
            username = self.lbaas_username
        else:
            password = self.admin_password
            project_id = self.admin_project_id
            username = self.admin_username

        return keystone_client.Client(
            username=username,
            password=password,
            auth_url=auth_url,
            tenant_id=project_id
        )

    def get_auth_token(self, lbaas_tenant=True):
        keystone_client = self.get_keystone_client(lbaas_tenant=lbaas_tenant)
        return keystone_client.auth_token

    def get_subnet_netmask(self, subnet_id):
        neutron = self.get_neutron_client()
        subnet = neutron.show_subnet(subnet_id)['subnet']
        return self.get_netmask(subnet['cidr'])

    def get_netmask(self, cidr):
        mask = int(cidr.split("/")[1])
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return socket.inet_ntoa(struct.pack('>I', bits))

    def ip_in_subnet(self, ip, cidr):
        ip_address = struct.unpack('!L', socket.inet_aton(ip))[0]
        network, mask_bits = cidr.split('/')
        network_address = struct.unpack('!L', socket.inet_aton(network))[0]
        netmask = (0xFFFFFFFF >> int(mask_bits)) ^ 0xFFFFFFFF
        return ip_address & netmask == network_address

    def _generate_user_data(self, hostname, password, data_port, mgmt_port,
                            cluster_data=None):
        neutron = self.get_neutron_client()
        data_subnet = neutron.show_subnet(
            data_port['fixed_ips'][0]['subnet_id']
        )['subnet']
        mgmt_subnet = neutron.show_subnet(
            mgmt_port['fixed_ips'][0]['subnet_id']
        )['subnet']
        # Get bind IP for management services
        if mgmt_port:
            bind_ip = mgmt_port['fixed_ips'][0]['ip_address']
        else:
            bind_ip = data_port['fixed_ips'][0]['ip_address']
        # Build the replay data to feed into the config script on the instance
        replay_data = {
            "developer_mode_accepted": "Yes",
            "admin!password": password,
            "rest!enabled": "Yes",
            "appliance!timezone": cfg.CONF.vtm_settings.timezone,
            "appliance!hostname": hostname,
            "appliance!licence_agreed": "Yes",
            "rest!port": cfg.CONF.vtm_settings.rest_port,
            "appliance!gateway": data_subnet['gateway_ip'] or mgmt_subnet['gateway_ip'],
            "appliance!if!eth0!autoneg": "Yes",
            "appliance!if!eth0!mtu": cfg.CONF.vtm_settings.mtu,
            "appliance!ip!eth0!isexternal": "No",
            "appliance!ssh!port": "2222",
            "rest!bindips": bind_ip,
            "control!bindip": bind_ip if cluster_data else "127.0.0.1",
            "flipper!frontend_check_addrs": "",
            "appliance!return_path_routing_enabled": "yes",
            "appliance!nameservers":
                " ".join(cfg.CONF.vtm_settings.nameservers)
        }
        # SNMP configuration
        if cfg.CONF.vtm_settings.snmp_enabled is True:
            replay_data['snmp!enabled'] = "Yes"
            replay_data['snmp!community'] = (
                cfg.CONF.vtm_settings.snmp_community
            )
            replay_data['snmp!bindip'] = bind_ip
            replay_data['snmp!allow'] = " ".join(
                cfg.CONF.vtm_settings.snmp_allow_from
            )
        # GUI user settings
        if cfg.CONF.vtm_settings.gui_access is True:
            replay_data['monitor_user'] = "monitor %s" % "password"
        else:
            replay_data.update({
                "access": " ".join(list(set([
                    socket.gethostbyname(server)
                    for server in cfg.CONF.lbaas_settings.configuration_source_ips
                ])))
            })
            if cluster_data:
                replay_data['access'] += " %s" % cluster_data['peer_addr']
        if mgmt_port:
            # Add static routes from subnet 'host_routes' fields
            for host_route in mgmt_subnet['host_routes']:
                dest = "appliance!routes!%s" % host_route['destination'].split("/")[0]
                replay_data["%s!if" % dest] = "eth0"
                replay_data["%s!mask" % dest] = self.get_netmask(host_route['destination'])
                replay_data["%s!gw" % dest] = host_route['nexthop']
            for host_route in data_subnet['host_routes']:
                dest = "appliance!routes!%s" % host_route['destination'].split("/")[0]
                replay_data["%s!if" % dest] = "eth1"
                replay_data["%s!mask" % dest] = self.get_netmask(host_route['destination'])
                replay_data["%s!gw" % dest] = host_route['nexthop']
            replay_data["appliance!hosts!%s" % hostname] = \
                mgmt_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!addr"] = \
                mgmt_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!mask"] = self.get_netmask(
                mgmt_subnet['cidr']
            )
            replay_data["appliance!if!eth1!autoneg"] = "Yes"
            replay_data["appliance!if!eth1!mtu"] = cfg.CONF.vtm_settings.mtu
            replay_data["appliance!ip!eth1!isexternal"] = "No"
            replay_data["appliance!ip!eth1!addr"] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth1!mask"] = self.get_netmask(
                data_subnet['cidr']
            )
        else:
            # Add static routes from subnet 'host_routes' field
            for host_route in data_subnet['host_routes']:
                dest = "appliance!routes!%s" % host_route['destination'].split("/")[0]
                replay_data["%s!if" % dest] = "eth0"
                replay_data["%s!mask" % dest] = self.get_netmask(host_route['destination'])
                replay_data["%s!gw" % dest] = host_route['nexthop']
            replay_data["appliance!hosts!%s" % hostname] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!addr"] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!mask"] = self.get_netmask(
                data_subnet['cidr']
            )
        if cluster_data:
            replay_data.update({
                "appliance!hosts!%s" % cluster_data['peer_name']:
                cluster_data['peer_addr'],
                "controlallow": "localhost,%s,%s" % (
                    bind_ip, cluster_data['peer_addr']
                )
            })
            if cluster_data['is_primary'] is False:
                cluster_join_data = {
                    "accept-license": "accept",
                    "start_at_boot": "y",
                    "zxtm!group": "nogroup",
                    "zxtm!license_key": "",
                    "zxtm!name_useip": "n",
                    "zxtm!use_invalid_key_license": "y",
                    "zxtm!user": "nobody",
                    "zxtm!cluster": "S",
                    "zxtm!clustertipjoin": "p",
                    "zxtm!fingerprints_ok": "y",
                    "zlb!admin_username": cfg.CONF.vtm_settings.username,
                    "zlb!admin_port": cfg.CONF.vtm_settings.admin_port,
                    "zlb!admin_hostname": cluster_data['peer_addr'],
                    "zlb!admin_password": password,
                    "zxtm!join_new_cluster": "y",
                    "zxtm!name_setname": "1",
                    "zxtm!reconfigure_option": "2"
                }
                if cfg.CONF.vtm_settings.gui_access is True:
                    cluster_join_data['zxtm!unique_bind'] = "n"
                else:
                    cluster_join_data['zxtm!unique_bind'] = "n"
                    cluster_join_data['zxtm!bindip'] = bind_ip
                cluster_join_text = "\n".join([
                    "%s=%s" % (k, v) for k, v in cluster_join_data.iteritems()
                ])
            elif cfg.CONF.vtm_settings.gui_access is not True:
                cluster_join_data = {
                    "accept-license": "accept",
                    "start_at_boot": "y",
                    "zxtm!group": "nogroup",
                    "zxtm!license_key": "",
                    "zxtm!name_useip": "n",
                    "zxtm!unique_bind": "y",
                    "zxtm!use_invalid_key_license": "y",
                    "zxtm!user": "nobody",
                    "zxtm!cluster": "C",
                    "zxtm!bindip": bind_ip,
                    "zxtm!join_new_cluster": "n",
                    "zxtm!name_setname": "1",
                    "zxtm!reconfigure_option": "2"
                }
                cluster_join_text = "\n".join([
                    "%s=%s" % (k, v) for k, v in cluster_join_data.iteritems()
                ])
            else:
                cluster_join_text = None
        else:
            cluster_join_text = None
        replay_text = "\n".join(
            ["%s\t%s" % (k, v) for k, v in replay_data.iteritems()]
        )
        return {
            "replay_data": replay_text,
            "cluster_join_data": cluster_join_text,
            "cluster_target": cluster_data['peer_addr'] if cluster_join_text else None,
            "password": password,
            "hostname": hostname
        }

    def _generate_cloud_init_file(self, user_data):
        return ("""#cloud-config
write_files:
-   encoding: b64
    content: {0}
    path: /root/config_data

-   content: |
        community       {1}
        snmp!version    snmpv2c
        traphost        {2}
        type    trap
    path: /opt/zeus/zxtm/conf/actions/lbaas_snmp_trap

-   content: |
        actions	lbaas_snmp_trap
        type!faulttolerance!event_tags  activatealldead allmachinesok flipperbackendsworking dropipinfo flipperfrontendsworking activatedautomatically flipperrecovered flipperraiselocalworking flipperraiseosdrop flipperraiseothersdead flipperdadreraise machinerecovered machineok stateok multihostload dropipwarn pingbackendfail zclustermoderr stateconnfail pingfrontendfail pinggwfail flipperipexists pingsendfail statereadfail statebaddata stateunexpected machinefail machinetimeout flipperraiseremotedropped statetimeout statewritefail routingswfailurelimitreached clocknotmonotonic clockjump
        type!general!event_tags running autherror logdiskoverload confrepfailed confreptimeout fewfreefds restartrequired timemovedback numtipg-exceeded sslcrltoobig numnodes-exceeded numpools-exceeded zxtmswerror zxtmcpustarvation zxtmhighload childcommsfail appliance
        type!licensekeys!event_tags     licensestate-malformed bwlimited expiresoon15 expiresoon30 expiresoon60 expiresoon license-rejected-unauthorized-ts license-rejected-authorized-ts ssltpslimited tpslimited license-rejected-unauthorized license-rejected-authorized license-graceperiodexpired license-timedout-unauthorized license-timedout-authorized licensestate-write-failed license-timedout-unauthorized-ts license-timedout-authorized-ts license-explicitlydisabled-ts expired licensecorrupt license-unauthorized license-graceperiodexpired-ts
        type!licensekeys!object_names   *
    path: /opt/zeus/zxtm/conf/events/lbaas_event

-   content: |
        type!faulttolerance!event_tags	allmachinesok
        actions	sync-cluster
    path: /opt/zeus/zxtm/conf/events/allmachinesok

-   content: |
        program	sync-cluster.py
        type	program
    path: /opt/zeus/zxtm/conf/actions/sync-cluster

-   content: |
        0
    path: /opt/zeus/zxtm/conf/extra/last_update

-   content: |
        #!/usr/bin/env python

        import requests
        import socket
        import subprocess

        def get_last_local_update():
            with open("/opt/zeus/zxtm/conf/extra/last_update") as f:
                last_update = f.readline()
            return int(last_update.strip())

        def get_last_remote_update():
            local_hostname = socket.gethostname()
            if local_hostname.endswith("-pri"):
                remote_hostname = local_hostname[:-3] + "sec"
            else:
                remote_hostname = local_hostname[:-3] + "pri"
            url = "https://%s:9070/api/tm/3.5/config/active/extra_files/last_update" % (
                remote_hostname
            )
            last_update = requests.get(url, auth=('admin', '{3}'), verify=False).text
            return int(last_update.strip())

        def main():
            if get_last_local_update() > get_last_remote_update():
                subprocess.call(["/opt/zeus/zxtm/bin/replicate-config"])

        if __name__ == '__main__':
            main()
    path: /opt/zeus/zxtm/conf/actionprogs/sync-cluster.py
    permissions: '0755'

-   encoding: b64
    content: """
"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiNDb3B5cmlnaHQgMjAxNCBCcm9jYWRlIENvbW11bmljYXRpb"
"25zIFN5c3RlbXMsIEluYy4gIEFsbCByaWdodHMgcmVzZXJ2ZWQuCgppbXBvcnQgb3MKaW1wb3J0IG"
"pzb24KaW1wb3J0IHNvY2tldApmcm9tIHN1YnByb2Nlc3MgaW1wb3J0IFBvcGVuLCBQSVBFLCBTVER"
"PVVQsIGNhbGwKZnJvbSB0aW1lIGltcG9ydCBzbGVlcAoKY2xhc3MgQ29uZmlnRmlsZShkaWN0KToK"
"ICAgIGRlZiBfX2luaXRfXyhzZWxmLCBuYW1lLCBwYXRoKToKICAgICAgICBzZWxmLmZpbGVuYW1lI"
"D0gIiVzLyVzIiAlIChwYXRoLCBuYW1lKQogICAgICAgIHNlbGYuX2dldF9jdXJyZW50X2tleXMoKQ"
"oKICAgIGRlZiBhcHBseShzZWxmKToKICAgICAgICB3aXRoIG9wZW4oc2VsZi5maWxlbmFtZSwgInc"
"iKSBhcyBjb25maWdfZmlsZToKICAgICAgICAgICAgZm9yIGtleSwgdmFsdWUgaW4gc2VsZi5pdGVy"
"aXRlbXMoKToKICAgICAgICAgICAgICAgIGNvbmZpZ19maWxlLndyaXRlKCIlc1x0JXNcbiIgJSAoa"
"2V5LCB2YWx1ZSkpCgogICAgZGVmIF9nZXRfY3VycmVudF9rZXlzKHNlbGYpOgogICAgICAgIHdpdG"
"ggb3BlbihzZWxmLmZpbGVuYW1lKSBhcyBjb25maWdfZmlsZToKICAgICAgICAgICAgZm9yIGxpbmU"
"gaW4gY29uZmlnX2ZpbGU6CiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICAgICAg"
"Yml0cyA9IGxpbmUuc3BsaXQoKQogICAgICAgICAgICAgICAgICAgIHNlbGZbYml0c1swXV0gPSAiI"
"CIuam9pbihiaXRzWzE6XSkKICAgICAgICAgICAgICAgIGV4Y2VwdDoKICAgICAgICAgICAgICAgIC"
"AgICBwYXNzCiAgICAgICAgCgpjbGFzcyBSZXBsYXlEYXRhKGRpY3QpOgogICAgY2xhc3MgUmVwbGF"
"5RGF0YVBhcmFtZXRlcihvYmplY3QpOgogICAgICAgIGRlZiBfX2luaXRfXyhzZWxmLCB0ZXh0KToK"
"ICAgICAgICAgICAgd29yZHMgPSB0ZXh0LnN0cmlwKCkuc3BsaXQoKQogICAgICAgICAgICBzZWxmL"
"mtleSA9IHdvcmRzWzBdCiAgICAgICAgICAgIHNlbGYucHJlZml4ID0gd29yZHNbMF0uc3BsaXQoIi"
"EiKVswXQogICAgICAgICAgICBzZWxmLnZhbHVlX2xpc3QgPSB3b3Jkc1sxOl0KICAgICAgICAgICA"
"gc2VsZi52YWx1ZV9zdHIgPSAiICIuam9pbih3b3Jkc1sxOl0pCgogICAgZGVmIF9faW5pdF9fKHNl"
"bGYsIHRleHQpOgogICAgICAgIGZvciBsaW5lIGluIHRleHQuc3BsaXQoIlxuIik6CiAgICAgICAgI"
"CAgIHdvcmRzID0gbGluZS5zcGxpdCgpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIH"
"NlbGZbd29yZHNbMF1dID0gc2VsZi5SZXBsYXlEYXRhUGFyYW1ldGVyKGxpbmUpCiAgICAgICAgICA"
"gIGV4Y2VwdCBJbmRleEVycm9yOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgIAoKZGVmIG1h"
"aW4oKToKICAgIFpFVVNIT01FID0gb3MuZW52aXJvbi5nZXQoJ1pFVVNIT01FJywgJy9vcHQvemV1c"
"ycpCiAgICBuZXdfdXNlciA9IE5vbmUKICAgIHV1aWRfZ2VuZXJhdGVfcHJvYyA9IFBvcGVuKAogIC"
"AgICAgIFsiJXMvenh0bS9iaW4vemNsaSIgJSBaRVVTSE9NRV0sCiAgICAgICAgc3Rkb3V0PVBJUEU"
"sIHN0ZGluPVBJUEUsIHN0ZGVycj1TVERPVVQKICAgICkKICAgIHV1aWRfZ2VuZXJhdGVfcHJvYy5j"
"b21tdW5pY2F0ZShpbnB1dD0iU3lzdGVtLk1hbmFnZW1lbnQucmVnZW5lcmF0ZVVVSUQiKVswXQogI"
"CAgY2FsbCgiJXMvc3RvcC16ZXVzIiAlIFpFVVNIT01FKQogICAgd2l0aCBvcGVuKCIvcm9vdC9jb2"
"5maWdfZGF0YSIpIGFzIGNvbmZpZ19kcml2ZToKICAgICAgICB1c2VyX2RhdGEgPSBqc29uLmxvYWR"
"zKGNvbmZpZ19kcml2ZS5yZWFkKCkpCiAgICBnbG9iYWxfY29uZmlnID0gQ29uZmlnRmlsZSgnZ2xv"
"YmFsLmNmZycsICIlcy96eHRtIiAlIFpFVVNIT01FKQogICAgc2V0dGluZ3NfY29uZmlnID0gQ29uZ"
"mlnRmlsZSgnc2V0dGluZ3MuY2ZnJywgIiVzL3p4dG0vY29uZiIgJSBaRVVTSE9NRSkKICAgIHNlY3"
"VyaXR5X2NvbmZpZyA9IENvbmZpZ0ZpbGUoJ3NlY3VyaXR5JywgIiVzL3p4dG0vY29uZiIgJSBaRVV"
"TSE9NRSkKICAgIHJlcGxheV9kYXRhID0gUmVwbGF5RGF0YSh1c2VyX2RhdGFbJ3JlcGxheV9kYXRh"
"J10pCiAgICBmb3IgcGFyYW1ldGVyIGluIHJlcGxheV9kYXRhLnZhbHVlcygpOgogICAgICAgIGlmI"
"HBhcmFtZXRlci5rZXkgPT0gImFkbWluIXBhc3N3b3JkIjoKICAgICAgICAgICAgcGFzc3dvcmRfcH"
"JvYyA9IFBvcGVuKAogICAgICAgICAgICAgICAgWyd6LXJlc2V0LXBhc3N3b3JkJ10sIAogICAgICA"
"gICAgICAgICAgc3Rkb3V0PVBJUEUsIHN0ZGluPVBJUEUsIHN0ZGVycj1TVERPVVQKICAgICAgICAg"
"ICAgKQogICAgICAgICAgICBzdGRvdXQgPSBwYXNzd29yZF9wcm9jLmNvbW11bmljYXRlKGlucHV0P"
"SIlc1xuJXMiICUgKAogICAgICAgICAgICAgICAgcGFyYW1ldGVyLnZhbHVlX3N0ciwgcGFyYW1ldG"
"VyLnZhbHVlX3N0cgogICAgICAgICAgICApKVswXQogICAgICAgIGVsaWYgcGFyYW1ldGVyLmtleSA"
"9PSAibW9uaXRvcl91c2VyIjoKICAgICAgICAgICAgbmV3X3VzZXIgPSB7IAogICAgICAgICAgICAg"
"ICAgInVzZXJuYW1lIjogcGFyYW1ldGVyLnZhbHVlX2xpc3RbMF0sCiAgICAgICAgICAgICAgICAic"
"GFzc3dvcmQiOiBwYXJhbWV0ZXIudmFsdWVfbGlzdFsxXSwKICAgICAgICAgICAgICAgICJncm91cC"
"I6ICJHdWVzdCIKICAgICAgICAgICAgfQogICAgICAgIGVsaWYgcGFyYW1ldGVyLmtleSBpbiBbICd"
"yZXN0IWVuYWJsZWQnLCAnY29udHJvbGFsbG93JyBdIFwKICAgICAgICBvciBwYXJhbWV0ZXIucHJl"
"Zml4IGluIFsgJ2ZsaXBwZXInIF0gXAogICAgICAgIG9yIHBhcmFtZXRlci5rZXkuc3RhcnRzd2l0a"
"CgiYXBwbGlhbmNlIXJldHVybnBhdGgiKSBcCiAgICAgICAgb3IgcGFyYW1ldGVyLmtleS5zdGFydH"
"N3aXRoKCJhcHBsaWFuY2UhcmV0dXJuX3BhdGgiKToKICAgICAgICAgICAgc2V0dGluZ3NfY29uZml"
"nW3BhcmFtZXRlci5rZXldID0gcGFyYW1ldGVyLnZhbHVlX3N0cgogICAgICAgIGVsaWYgcGFyYW1l"
"dGVyLmtleSBpbiBbICdkZXZlbG9wZXJfbW9kZV9hY2NlcHRlZCcsICduYW1laXAnIF06CiAgICAgI"
"CAgICAgIGdsb2JhbF9jb25maWdbcGFyYW1ldGVyLmtleV0gPSBwYXJhbWV0ZXIudmFsdWVfc3RyCi"
"AgICAgICAgZWxpZiBwYXJhbWV0ZXIucHJlZml4IGluIFsgJ2FwcGxpYW5jZScsICdyZXN0JywgJ2N"
"vbnRyb2wnLCAnc25tcCcgXToKICAgICAgICAgICAgZ2xvYmFsX2NvbmZpZ1twYXJhbWV0ZXIua2V5"
"XSA9IHBhcmFtZXRlci52YWx1ZV9zdHIKICAgICAgICBlbGlmIHBhcmFtZXRlci5rZXkgaW4gWyAnY"
"WNjZXNzJyBdOgogICAgICAgICAgICBzZWN1cml0eV9jb25maWdbcGFyYW1ldGVyLmtleV0gPSBwYX"
"JhbWV0ZXIudmFsdWVfc3RyCiAgICBnbG9iYWxfY29uZmlnLmFwcGx5KCkKICAgIHNldHRpbmdzX2N"
"vbmZpZy5hcHBseSgpCiAgICBzZWN1cml0eV9jb25maWcuYXBwbHkoKQogICAgb3MucmVtb3ZlKCIl"
"cy96eHRtL2dsb2JhbC5jZmciICUgWkVVU0hPTUUpCiAgICBvcy5yZW5hbWUoCiAgICAgICAgIiVzL"
"3p4dG0vY29uZi96eHRtcy8obm9uZSkiICUgWkVVU0hPTUUsIAogICAgICAgICIlcy96eHRtL2Nvbm"
"Yvenh0bXMvJXMiICUgKFpFVVNIT01FLCB1c2VyX2RhdGFbJ2hvc3RuYW1lJ10pCiAgICApCiAgICB"
"vcy5zeW1saW5rKAogICAgICAgICIlcy96eHRtL2NvbmYvenh0bXMvJXMiICUgKFpFVVNIT01FLCB1"
"c2VyX2RhdGFbJ2hvc3RuYW1lJ10pLCAKICAgICAgICAiJXMvenh0bS9nbG9iYWwuY2ZnIiAlIFpFV"
"VNIT01FCiAgICApCiAgICBjYWxsKFsgIiVzL3p4dG0vYmluL3N5c2NvbmZpZyIgJSBaRVVTSE9NRS"
"wgIi0tYXBwbHkiIF0pCiAgICBjYWxsKCIlcy9zdGFydC16ZXVzIiAlIFpFVVNIT01FKQogICAgaWY"
"gbmV3X3VzZXIgaXMgbm90IE5vbmU6CiAgICAgICAgdXNlcl9wcm9jID0gUG9wZW4oCiAgICAgICAg"
"ICAgIFsiJXMvenh0bS9iaW4vemNsaSIgJSBaRVVTSE9NRV0sCiAgICAgICAgICAgIHN0ZG91dD1QS"
"VBFLCBzdGRpbj1QSVBFLCBzdGRlcnI9U1RET1VUCiAgICAgICAgKQogICAgICAgIHVzZXJfcHJvYy"
"5jb21tdW5pY2F0ZShpbnB1dD0iVXNlcnMuYWRkVXNlciAlcywgJXMsICVzIiAlICgKICAgICAgICA"
"gICAgbmV3X3VzZXJbJ3VzZXJuYW1lJ10sIG5ld191c2VyWydwYXNzd29yZCddLCBuZXdfdXNlclsn"
"Z3JvdXAnXQogICAgICAgICkpWzBdCiAgICBpZiB1c2VyX2RhdGFbJ2NsdXN0ZXJfam9pbl9kYXRhJ"
"10gaXMgbm90IE5vbmU6CiAgICAgICAgd2l0aCBvcGVuKCIvdG1wL3JlcGxheV9kYXRhIiwgInciKS"
"BhcyByZXBsYXlfZmlsZToKICAgICAgICAgICAgcmVwbGF5X2ZpbGUud3JpdGUodXNlcl9kYXRhWyd"
"jbHVzdGVyX2pvaW5fZGF0YSddKQogICAgICAgIGlmIHVzZXJfZGF0YVsnY2x1c3Rlcl90YXJnZXQn"
"XSBpcyBub3QgTm9uZToKICAgICAgICAgICAgcyA9IHNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lOR"
"VQsIHNvY2tldC5TT0NLX1NUUkVBTSkKICAgICAgICAgICAgcy5zZXR0aW1lb3V0KDMpCiAgICAgIC"
"AgICAgIGZvciBfIGluIHhyYW5nZSg2MCk6CiAgICAgICAgICAgICAgICB0cnk6CiAgICAgICAgICA"
"gICAgICAgICAgcy5jb25uZWN0KCh1c2VyX2RhdGFbJ2NsdXN0ZXJfdGFyZ2V0J10sIDkwNzApKQog"
"ICAgICAgICAgICAgICAgZXhjZXB0IHNvY2tldC5lcnJvcjoKICAgICAgICAgICAgICAgICAgICBzb"
"GVlcCgyKQogICAgICAgICAgICAgICAgZXhjZXB0IHNvY2tldC5nYWllcnJvcjoKICAgICAgICAgIC"
"AgICAgICAgICBicmVhawogICAgICAgICAgICBzLmNsb3NlKCkKICAgICAgICBjYWxsKFsgIiVzL3p"
"4dG0vY29uZmlndXJlIiAlIFpFVVNIT01FLCAiLS1yZXBsYXktZnJvbT0vdG1wL3JlcGxheV9kYXRh"
"IiBdKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBtYWluKCkK"
"""
    path: /root/configure.py

runcmd:
-   [ "python", "/root/configure.py" ]
    """.format(
        base64.b64encode(json.dumps(user_data)),
        cfg.CONF.vtm_settings.snmp_community,
        cfg.CONF.vtm_settings.snmp_traphost,
        user_data['password']
    ))
