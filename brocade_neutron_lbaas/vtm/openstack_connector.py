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
from keystoneclient.v3 import client as keystone_client
from neutronclient.neutron import client as neutron_client
from oslo_log import log as logging
from oslo.config import cfg
from random import choice, randint
import requests
import socket
from string import ascii_letters, digits
from struct import pack
from time import sleep

LOG = logging.getLogger(__name__)


class OpenStackInterface(object):
    def __init__(self):
        self.admin_username = cfg.CONF.lbaas_settings.openstack_username
        self.admin_password = cfg.CONF.lbaas_settings.openstack_password
        # Get Neutron and Nova API endpoints...
        keystone = self.get_keystone_client()
        neutron_service = keystone.services.find(name="neutron")
        nova_service = keystone.services.find(name="nova")
        self.neutron_endpoint = keystone.endpoints.find(
            interface="admin", service_id=neutron_service.id
        ).url
        self.nova_endpoint = keystone.endpoints.find(
            interface="admin", service_id=nova_service.id
        ).url

    def create_vtm(self, hostname, lb, license_key):
        """
        Creates a vTM instance as a Nova VM.
        """
        password = self._generate_password()
        # Get NIC and IP information for the instance to be created
        if cfg.CONF.lbaas_settings.deployment_model == "PER_LOADBALANCER":
            use_lb_port = True
        else:
            use_lb_port = False
        net_info = self._configure_ports(lb, hostname, use_lb_port)
        # Get user-data to pass to the configuration scripts in the
        # vTM image
        user_data = self._generate_user_data(
            hostname, password, net_info['data_port'], net_info['mgmt_port']
        )
        user_data['license_key'] = license_key
        cloud_init_file = self._generate_cloud_init_file(user_data)
        self.boot_vtm(lb.tenant_id, hostname, cloud_init_file,
                      net_info['nics'], password)
        return (net_info['mgmt_ip'], password)

    def create_vtms(self, hostnames, lb, license_key):
        """
        Creates an HA cluster of vTM instances.
        """
        password = self._generate_password()
        # Configure ports and security groups for both instances
        primary_net_info = self._configure_ports(
            lb, hostnames[0], False, cluster=True
        )
        security_groups = {
            "ports": primary_net_info['ports_sec_grp'],
            "mgmt": primary_net_info['mgmt_sec_grp']
        }
        secondary_net_info = self._configure_ports(
            lb, hostnames[1], False, security_groups, True
        )
        # Create primary instance
        primary_user_data = self._generate_user_data(
            hostnames[0], password,
            primary_net_info['data_port'],
            primary_net_info['mgmt_port'],
            {
                "is_primary": True,
                "peer_name": hostnames[1],
                "peer_addr": secondary_net_info['cluster_addr']
            }
        )
        primary_user_data['license_key'] = license_key
        cloud_init_file = self._generate_cloud_init_file(primary_user_data)
        self.boot_vtm(
            lb.tenant_id, hostnames[0],
            cloud_init_file, primary_net_info['nics'], password
        )
        # Give the primary chance to come up and stabilize
        # before the second instance tries to cluster to it
        sleep(10)
        # Create secondary instance
        secondary_user_data = self._generate_user_data(
            hostnames[1], password,
            secondary_net_info['data_port'],
            secondary_net_info['mgmt_port'],
            {
                "is_primary": False,
                "peer_name": hostnames[0],
                "peer_addr": primary_net_info['cluster_addr']
            }
        )
        secondary_user_data['license_key'] = license_key
        cloud_init_file = self._generate_cloud_init_file(secondary_user_data)
        self.boot_vtm(
            lb.tenant_id, hostnames[1],
            cloud_init_file, secondary_net_info['nics'], password
        )
        return {
            "password": password,
            "nodes": [
                {
                    "hostname": hostnames[0],
                    "mgmt_ip": primary_net_info['mgmt_ip']
                },
                {
                    "hostname": hostnames[1],
                    "mgmt_ip": secondary_net_info['mgmt_ip']
                }
            ]
        }

    def boot_vtm(self, tenant_id, hostname, user_data, nics, password):
        """
        Boots a vTM instance.
        """
        instance = self.create_server(
            tenant_id=tenant_id,
            hostname=hostname,
            user_data=user_data,
            nics=nics,
            password=password
        )
        self.lock_server(tenant_id, instance['server']['id'])
        self._await_build_complete(tenant_id, instance['server']['id'])
        return instance

    def destroy_vtm(self, hostname, lb):
        port_list = []
        sec_grp_list = []
        floatingip_list = []
        server_id = self.get_server_id_from_hostname(lb.tenant_id, hostname)
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
        self.delete_server(lb.tenant_id, server_id)
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

    def vtm_exists(self, tenant_id, hostname):
        """
        Tests whether a vTM instance with the specified hosname exists.
        """
        hostname = hostname[0] if isinstance(hostname, tuple) else hostname
        try:
            self.get_server_id_from_hostname(tenant_id, hostname)
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

    def _await_build_complete(self, tenant_id, instance_id):
        """
        Waits for a Nova instance to be built.
        """
        instance = self.get_server(tenant_id, instance_id)
        status = instance['server']['status']
        while status == 'BUILD':
            sleep(10)
            instance = self.get_server(tenant_id, instance_id)
            status = instance['server']['status']
            if status == 'ERROR':
                self.delete_server(tenant_id, instance_id)
                raise Exception("VM build failed")

    def _configure_ports(self, lb, hostname, use_lb_port, security_groups=None,
                         cluster=False):
        neutron = self.get_neutron_client()
        # Get or create port, depending on deployment model...
        if use_lb_port is True:
            # Data port will be the port associated with the "loadbalancer"
            data_port = neutron.show_port(lb.vip_port_id)['port']
            sec_grp_uuid = lb.id
        else:
            # A new port, not tied to a "loadbalancer", is needed as the
            # instance's main address (so it isn't deleted when the "lb" is).
            network_id = neutron.show_subnet(
                lb.vip_subnet_id
            )['subnet']['network_id']
            data_port = neutron.create_port(
                {"port": {
                    "network_id": network_id,
                    "tenant_id": lb.tenant_id
                }}
            )['port']
            if cfg.CONF.lbaas_settings.deployment_model == "PER_LOADBALANCER":
                sec_grp_uuid = lb.id
            elif cfg.CONF.lbaas_settings.deployment_model == "PER_TENANT":
                sec_grp_uuid = lb.tenant_id

        # Configure specified management method...
        data = {
            "data_port": data_port
        }
        if cfg.CONF.lbaas_settings.management_mode == "FLOATING_IP":
            # Create floating IP for management traffic
            floatingip = self.create_floatingip(lb.tenant_id, data_port['id'])
            if security_groups is None:
                # Create security group and add rules for management traffic
                sec_grp = self.create_lb_security_group(
                    lb.tenant_id, sec_grp_uuid, mgmt_port=True, cluster=cluster
                )
                sec_grp_id = sec_grp['security_group']['id']
            else:
                # Use an existing security group
                sec_grp_id = security_groups['ports']
            neutron.update_port(
                data_port['id'],
                {"port": {
                    "security_groups": [sec_grp_id],
                    "admin_state_up": True
                }}
            )
            # Set return data
            if cluster:
                data['cluster_addr'] = data_port['fixed_ips'][0]['ip_address']
            else:
                data['cluster_addr'] = None
            data['nics'] = [{"port": data_port['id']}]
            data['ports_sec_grp'] = sec_grp_id
            data['mgmt_sec_grp'] = None
            data['mgmt_ip'] = floatingip['floatingip']['floating_ip_address']
            data['mgmt_port'] = None
        elif cfg.CONF.lbaas_settings.management_mode == "MGMT_NET":
            if security_groups is None:
                # Create a security groups for the service and management ports
                ports_sec_grp = self.create_lb_security_group(
                    lb.tenant_id, sec_grp_uuid
                )
                mgmt_sec_grp = self.create_lb_security_group(
                    lb.tenant_id, sec_grp_uuid, mgmt_port=True,
                    mgmt_label=True, cluster=cluster
                )
                ports_sec_grp_id = ports_sec_grp['security_group']['id']
                mgmt_sec_grp_id = mgmt_sec_grp['security_group']['id']
            else:
                # Use existing security groups
                ports_sec_grp_id = security_groups['ports']
                mgmt_sec_grp_id = security_groups['mgmt']
            # Update data port with security group
            neutron.update_port(
                data_port['id'],
                {"port": {
                    "security_groups": [ports_sec_grp_id],
                    "admin_state_up": True
                }}
            )
            # Create the management port
            mgmt_port = self.create_mgmt_port(
                lb.tenant_id, hostname, mgmt_sec_grp_id
            )['port']
            # Set return data
            if cluster:
                data['cluster_addr'] = mgmt_port['fixed_ips'][0]['ip_address']
            else:
                data['cluster_addr'] = None
            data['nics'] = [
                {"port": mgmt_port['id']},
                {"port": data_port['id']}
            ]
            data['ports_sec_grp'] = ports_sec_grp_id
            data['mgmt_sec_grp'] = mgmt_sec_grp_id
            data['mgmt_ip'] = mgmt_port['fixed_ips'][0]['ip_address']
            data['mgmt_port'] = mgmt_port
        return data

    def create_lb_security_group(self, tenant_id, uuid, mgmt_port=False,
                                 mgmt_label=False, cluster=False):
        """
        Creates a security group.
        """
        neutron = self.get_neutron_client()
        sec_grp_data = {"security_group": {
            "name": "%slbaas-%s" % ("mgmt-" if mgmt_label else "", uuid),
            "tenant_id": tenant_id
        }}
        sec_grp = neutron.create_security_group(sec_grp_data)
        # If GUI access is allowed, open up the GUI port
        if cfg.CONF.vtm_settings.gui_access is True and not mgmt_label:
            self.create_security_group_rule(
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port
            )
        # If mgmt_port, add the necessary rules to allow management traffic
        # i.e. allow each Services Director to access the REST port of the
        # instance
        if mgmt_port:
            for server in cfg.CONF.lbaas_settings.admin_servers:
                self.create_security_group_rule(
                    sec_grp['security_group']['id'],
                    port=cfg.CONF.vtm_settings.rest_port,
                    src_addr=socket.gethostbyname(server)
                )
            if cfg.CONF.lbaas_settings.neutron_servers is not None:
                for server in cfg.CONF.lbaas_settings.neutron_servers:
                    self.create_security_group_rule(
                        sec_grp['security_group']['id'],
                        port=cfg.CONF.vtm_settings.rest_port,
                        src_addr=socket.gethostbyname(server)
                    )
        # If cluster, add necessary ports for intra-cluster comms
        if cluster is True:
            self.create_security_group_rule(
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port,
                remote_group=sec_grp['security_group']['id']
            )
            self.create_security_group_rule(
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port,
                remote_group=sec_grp['security_group']['id'],
                protocol='udp'
            )
            self.create_security_group_rule(
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.cluster_port,
                remote_group=sec_grp['security_group']['id']
            )
            self.create_security_group_rule(
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.cluster_port,
                remote_group=sec_grp['security_group']['id'],
                protocol='udp'
            )
        return sec_grp

    def create_security_group_rule(self, sec_grp_id, port, src_addr=None,
                                   remote_group=None, direction="ingress",
                                   protocol='tcp'):
        """
        Creates the designatted rule in a security group.
        """
        neutron = self.get_neutron_client()
        new_rule = {"security_group_rule": {
            "direction": direction,
            "port_range_min": port,
            "ethertype": "IPv4",
            "port_range_max": port,
            "protocol": protocol,
            "security_group_id": sec_grp_id
        }}
        if src_addr:
            new_rule['security_group_rule']['remote_ip_prefix'] = src_addr
        if remote_group:
            new_rule['security_group_rule']['remote_group_id'] = remote_group
        try:
            neutron.create_security_group_rule(new_rule)
        except Exception:
            # Rule already exists
            pass

    def allow_port(self, lb, port, protocol='tcp'):
        """
        Adds access to a given port to a security group.
        """
        # Get the name of the security group for the "loadbalancer"
        if cfg.CONF.lbaas_settings.deployment_model == "PER_LOADBALANCER":
            sec_grp_name = "lbaas-%s" % lb.id
        elif cfg.CONF.lbaas_settings.deployment_model == "PER_TENANT":
            sec_grp_name = "lbaas-%s" % lb.tenant_id
        # Get the security group
        neutron = self.get_neutron_client()
        sec_grp = neutron.list_security_groups(
            name=sec_grp_name
        )['security_groups'][0]
        # Create the required rule
        self.create_security_group_rule(sec_grp['id'], port, protocol=protocol)

    def block_port(self, lb, port, protocol='tcp'):
        """
        Removes access to a given port from a security group.
        """
        # Get the name of the security group for the "loadbalancer"
        if cfg.CONF.lbaas_settings.deployment_model == "PER_LOADBALANCER":
            sec_grp_name = "lbaas-%s" % lb.id
        elif cfg.CONF.lbaas_settings.deployment_model == "PER_TENANT":
            sec_grp_name = "lbaas-%s" % lb.tenant_id
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

    def create_mgmt_port(self, tenant_id, hostname, mgmt_sec_grp):
        """
        Creates a port for management traffic.
        """
        mgmt_net_id = cfg.CONF.lbaas_settings.management_network
        neutron = self.get_neutron_client()
        port = {
            "port": {
                "admin_state_up": True,
                "name": "mgmt-%s" % hostname,
                "network_id": mgmt_net_id,
                "security_groups": [mgmt_sec_grp],
                "tenant_id": tenant_id
            }
        }
        mgmt_port = neutron.create_port(port)
        return mgmt_port

    def create_floatingip(self, tenant_id, port_id):
        neutron = self.get_neutron_client()
        network = cfg.CONF.lbaas_settings.management_network
        floatingip_data = {"floatingip": {
            "floating_network_id": network,
            "port_id": port_id,
            "tenant_id": tenant_id
        }}
        return neutron.create_floatingip(floatingip_data)

    def create_server(self, tenant_id, hostname, user_data, nics, password):
        """
        Creates a Nova instance of the vTM image.
        """
        token = self.get_auth_token(tenant_id=tenant_id)
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
        try:
            response = requests.post(
                "%s/servers" % (
                    self.nova_endpoint.replace("$(tenant_id)s", tenant_id)
                ),
                data=json.dumps(body),
                headers=headers
            )
        except Exception as e:
            LOG.error(_("\nError creating vTM instance: %s" % e))
        return response.json()

    def get_server(self, tenant_id, server_id):
        token = self.get_auth_token(tenant_id=tenant_id)
        response = requests.get(
            "%s/servers/%s" % (
                self.nova_endpoint.replace("$(tenant_id)s", tenant_id),
                server_id
            ),
            headers={"X-Auth-Token": token}
        )
        if response.status_code != 200:
            raise Exception("Server Not found")
        return response.json()

    def lock_server(self, tenant_id, server_id):
        token = self.get_auth_token(tenant_id=tenant_id)
        response = requests.post(
            "%s/servers/%s/action" % (
                self.nova_endpoint.replace("$(tenant_id)s", tenant_id),
                server_id
            ),
            headers={
                "X-Auth-Token": token,
                "Content-Type": "application/json"
            },
            data='{ "lock": null }'
        )
        if response.status_code != 202:
            raise Exception("Failed to lock server %s" % server_id)

    def get_server_port(self, tenant_id, hostname):
        """
        Gets the Neutron ID of a vTM's data ort.
        """
        neutron = self.get_neutron_client()
        server_id = self.get_server_id_from_hostname(tenant_id, hostname)
        ports = neutron.list_ports(device_id=server_id)['ports']
        for port in ports:
            if not port['name'].startswith("mgmt"):
                return port['id']
        raise Exception("No data port found for %s" % hostname)

    def get_server_id_from_hostname(self, tenant_id, hostname):
        """
        Gets the Nova ID of a server from its hostname.
        """
        token = self.get_auth_token(tenant_id=tenant_id)
        response = requests.get(
            "%s/servers" % (
                self.nova_endpoint.replace("$(tenant_id)s", tenant_id)
            ),
            headers={"X-Auth-Token": token}
        )
        for server in response.json()['servers']:
            if server['name'] == hostname:
                return server['id']
        raise Exception("Server not found")

    def delete_server(self, tenant_id, server_id):
        """
        Deletes a Nova instance.
        """
        token = self.get_auth_token(tenant_id=tenant_id)
        requests.delete(
            "%s/servers/%s" % (
                self.nova_endpoint.replace("$(tenant_id)s", tenant_id),
                server_id
            ),
            headers={"X-Auth-Token": token}
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
            #cfg.CONF.keystone_authtoken.auth_protocol,
            "http",
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

    def get_netmask(self, cidr):
        mask = int(cidr.split("/")[1])
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return socket.inet_ntoa(pack('>I', bits))

    def _generate_password(self):
        chars = ascii_letters + digits
        return "".join(choice(chars) for _ in range(randint(12, 16)))

    def _generate_user_data(self, hostname, password, data_port, mgmt_port,
                            cluster_data=None):
        neutron = self.get_neutron_client()
        data_subnet = neutron.show_subnet(
            data_port['fixed_ips'][0]['subnet_id']
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
            "appliance!if!eth0!autoneg": "Yes",
            "appliance!if!eth0!mtu": "1454",
            "appliance!ip!eth0!isexternal": "No",
            "rest!bindips": bind_ip,
            "control!bindip": bind_ip if cluster_data else "127.0.0.1",
            "appliance!nameservers":
                " ".join(cfg.CONF.vtm_settings.nameservers)
        }
        replay_data.update({
            "appliance!hosts!%s" % server: socket.gethostbyname(server)
            for server in cfg.CONF.lbaas_settings.admin_servers
        })
        if cfg.CONF.vtm_settings.gui_access is True:
            replay_data['monitor_user'] = "tenant %s" % "admin"
        else:
            replay_data.update({
                "access": " ".join(list(set([
                    socket.gethostbyname(server)
                    for server in cfg.CONF.lbaas_settings.admin_servers
                ])))
            })
            if cluster_data:
                replay_data['access'] += " %s" % cluster_data['peer_addr']
        if mgmt_port:
            mgmt_subnet = neutron.show_subnet(
                mgmt_port['fixed_ips'][0]['subnet_id']
            )['subnet']
            replay_data["appliance!hosts!%s" % hostname] = \
                mgmt_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!addr"] = \
                mgmt_port['fixed_ips'][0]['ip_address']
            mgmt_subnet = neutron.show_subnet(
                mgmt_port['fixed_ips'][0]['subnet_id']
            )['subnet']
            replay_data["appliance!gateway"] = mgmt_subnet['gateway_ip']
            replay_data["appliance!ip!eth0!mask"] = self.get_netmask(
                mgmt_subnet['cidr']
            )
            replay_data["appliance!if!eth1!autoneg"] = "Yes"
            replay_data["appliance!if!eth1!mtu"] = "1454"
            replay_data["appliance!ip!eth1!isexternal"] = "No"
            replay_data["appliance!ip!eth1!addr"] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth1!mask"] = self.get_netmask(
                data_subnet['cidr']
            )
        else:
            replay_data["appliance!hosts!%s" % hostname] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!addr"] = \
                data_port['fixed_ips'][0]['ip_address']
            replay_data["appliance!ip!eth0!mask"] = self.get_netmask(
                data_subnet['cidr']
            )
            replay_data["appliance!gateway"] = data_subnet['gateway_ip']
        if cluster_data:
            replay_data.update({
                "appliance!hosts!%s" % cluster_data['peer_name']:
                cluster_data['peer_addr'],
                "controlallow": cluster_data['peer_addr']
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
                    "zxtm!clustertipjoin": "y",
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
            "password": password,
            "hostname": hostname
        }

    def _generate_cloud_init_file(self, user_data):
        return ("""#cloud-config
write_files:
-   encoding: b64
    content: %s
    path: /root/config_data

-   encoding: b64
    content: """
"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiNDb3B5cmlnaHQgMjAxNCBCcm9jYWRlIENvbW11bmljYXR"
"pb25zIFN5c3RlbXMsIEluYy4gIEFsbCByaWdodHMgcmVzZXJ2ZWQuCgppbXBvcnQgb3MKaW1wb3"
"J0IGpzb24KZnJvbSBzdWJwcm9jZXNzIGltcG9ydCBQb3BlbiwgUElQRSwgU1RET1VULCBjYWxsC"
"gpjbGFzcyBDb25maWdGaWxlKGRpY3QpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG5hbWUsIHBh"
"dGgpOgogICAgICAgIHNlbGYuZmlsZW5hbWUgPSAiJXMvJXMiICUgKHBhdGgsIG5hbWUpCiAgICA"
"gICAgc2VsZi5fZ2V0X2N1cnJlbnRfa2V5cygpCgogICAgZGVmIGFwcGx5KHNlbGYpOgogICAgIC"
"AgIHdpdGggb3BlbihzZWxmLmZpbGVuYW1lLCAidyIpIGFzIGNvbmZpZ19maWxlOgogICAgICAgI"
"CAgICBmb3Iga2V5LCB2YWx1ZSBpbiBzZWxmLml0ZXJpdGVtcygpOgogICAgICAgICAgICAgICAg"
"Y29uZmlnX2ZpbGUud3JpdGUoIiVzXHQlc1xuIiAlIChrZXksIHZhbHVlKSkKCiAgICBkZWYgX2d"
"ldF9jdXJyZW50X2tleXMoc2VsZik6CiAgICAgICAgd2l0aCBvcGVuKHNlbGYuZmlsZW5hbWUpIG"
"FzIGNvbmZpZ19maWxlOgogICAgICAgICAgICBmb3IgbGluZSBpbiBjb25maWdfZmlsZToKICAgI"
"CAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBiaXRzID0gbGluZS5zcGxpdCgp"
"CiAgICAgICAgICAgICAgICAgICAgc2VsZltiaXRzWzBdXSA9ICIgIi5qb2luKGJpdHNbMTpdKQo"
"gICAgICAgICAgICAgICAgZXhjZXB0OgogICAgICAgICAgICAgICAgICAgIHBhc3MKICAgICAgIC"
"AKCmNsYXNzIFJlcGxheURhdGEoZGljdCk6CiAgICBjbGFzcyBSZXBsYXlEYXRhUGFyYW1ldGVyK"
"G9iamVjdCk6CiAgICAgICAgZGVmIF9faW5pdF9fKHNlbGYsIHRleHQpOgogICAgICAgICAgICB3"
"b3JkcyA9IHRleHQuc3RyaXAoKS5zcGxpdCgpCiAgICAgICAgICAgIHNlbGYua2V5ID0gd29yZHN"
"bMF0KICAgICAgICAgICAgc2VsZi5wcmVmaXggPSB3b3Jkc1swXS5zcGxpdCgiISIpWzBdCiAgIC"
"AgICAgICAgIHNlbGYudmFsdWVfbGlzdCA9IHdvcmRzWzE6XQogICAgICAgICAgICBzZWxmLnZhb"
"HVlX3N0ciA9ICIgIi5qb2luKHdvcmRzWzE6XSkKCiAgICBkZWYgX19pbml0X18oc2VsZiwgdGV4"
"dCk6CiAgICAgICAgZm9yIGxpbmUgaW4gdGV4dC5zcGxpdCgiXG4iKToKICAgICAgICAgICAgd29"
"yZHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc2VsZl"
"t3b3Jkc1swXV0gPSBzZWxmLlJlcGxheURhdGFQYXJhbWV0ZXIobGluZSkKICAgICAgICAgICAgZ"
"XhjZXB0IEluZGV4RXJyb3I6CiAgICAgICAgICAgICAgICBwYXNzCiAgICAgICAgCgpkZWYgbWFp"
"bigpOgogICAgWkVVU0hPTUUgPSBvcy5lbnZpcm9uLmdldCgnWkVVU0hPTUUnLCAnL29wdC96ZXV"
"zJykKICAgIG5ld191c2VyID0gTm9uZQogICAgY2FsbCgiJXMvc3RvcC16ZXVzIiAlIFpFVVNIT0"
"1FKQogICAgd2l0aCBvcGVuKCIvcm9vdC9jb25maWdfZGF0YSIpIGFzIGNvbmZpZ19kYXRhOgogI"
"CAgICAgIHVzZXJfZGF0YSA9IGpzb24ubG9hZHMoY29uZmlnX2RhdGEucmVhZCgpKQogICAgd2l0"
"aCBvcGVuKCIlcy96eHRtL2NvbmYvbGljZW5zZWtleXMvbGljZW5zZS50eHQiICUgWkVVU0hPTUU"
"sICJ3IikgYXMgbGs6CiAgICAgICAgbGsud3JpdGUodXNlcl9kYXRhWydsaWNlbnNlX2tleSddKQ"
"ogICAgZ2xvYmFsX2NvbmZpZyA9IENvbmZpZ0ZpbGUoJ2dsb2JhbC5jZmcnLCAiJXMvenh0bSIgJ"
"SBaRVVTSE9NRSkKICAgIHNldHRpbmdzX2NvbmZpZyA9IENvbmZpZ0ZpbGUoJ3NldHRpbmdzLmNm"
"ZycsICIlcy96eHRtL2NvbmYiICUgWkVVU0hPTUUpCiAgICBzZWN1cml0eV9jb25maWcgPSBDb25"
"maWdGaWxlKCdzZWN1cml0eScsICIlcy96eHRtL2NvbmYiICUgWkVVU0hPTUUpCiAgICByZXBsYX"
"lfZGF0YSA9IFJlcGxheURhdGEodXNlcl9kYXRhWydyZXBsYXlfZGF0YSddKQogICAgZm9yIHBhc"
"mFtZXRlciBpbiByZXBsYXlfZGF0YS52YWx1ZXMoKToKICAgICAgICBpZiBwYXJhbWV0ZXIua2V5"
"ID09ICJhZG1pbiFwYXNzd29yZCI6CiAgICAgICAgICAgIHBhc3N3b3JkX3Byb2MgPSBQb3Blbig"
"KICAgICAgICAgICAgICAgIFsnei1yZXNldC1wYXNzd29yZCddLCAKICAgICAgICAgICAgICAgIH"
"N0ZG91dD1QSVBFLCBzdGRpbj1QSVBFLCBzdGRlcnI9U1RET1VUCiAgICAgICAgICAgICkKICAgI"
"CAgICAgICAgc3Rkb3V0ID0gcGFzc3dvcmRfcHJvYy5jb21tdW5pY2F0ZShpbnB1dD0iJXNcbiVz"
"IiAlICgKICAgICAgICAgICAgICAgIHBhcmFtZXRlci52YWx1ZV9zdHIsIHBhcmFtZXRlci52YWx"
"1ZV9zdHIKICAgICAgICAgICAgKSlbMF0KICAgICAgICBlbGlmIHBhcmFtZXRlci5rZXkgPT0gIm"
"1vbml0b3JfdXNlciI6CiAgICAgICAgICAgIG5ld191c2VyID0geyAKICAgICAgICAgICAgICAgI"
"CJ1c2VybmFtZSI6IHBhcmFtZXRlci52YWx1ZV9saXN0WzBdLAogICAgICAgICAgICAgICAgInBh"
"c3N3b3JkIjogcGFyYW1ldGVyLnZhbHVlX2xpc3RbMV0sCiAgICAgICAgICAgICAgICAiZ3JvdXA"
"iOiAiR3Vlc3QiCiAgICAgICAgICAgIH0KICAgICAgICBlbGlmIHBhcmFtZXRlci5rZXkgaW4gWy"
"AncmVzdCFlbmFibGVkJywgJ2NvbnRyb2xhbGxvdycgXToKICAgICAgICAgICAgc2V0dGluZ3NfY"
"29uZmlnW3BhcmFtZXRlci5rZXldID0gcGFyYW1ldGVyLnZhbHVlX3N0cgogICAgICAgIGVsaWYg"
"cGFyYW1ldGVyLmtleSBpbiBbICdkZXZlbG9wZXJfbW9kZV9hY2NlcHRlZCcsICduYW1laXAnIF0"
"6CiAgICAgICAgICAgIGdsb2JhbF9jb25maWdbcGFyYW1ldGVyLmtleV0gPSBwYXJhbWV0ZXIudm"
"FsdWVfc3RyCiAgICAgICAgZWxpZiBwYXJhbWV0ZXIucHJlZml4IGluIFsgJ2FwcGxpYW5jZScsI"
"CdyZXN0JywgJ2NvbnRyb2wnIF06CiAgICAgICAgICAgIGdsb2JhbF9jb25maWdbcGFyYW1ldGVy"
"LmtleV0gPSBwYXJhbWV0ZXIudmFsdWVfc3RyCiAgICAgICAgZWxpZiBwYXJhbWV0ZXIua2V5IGl"
"uIFsgJ2FjY2VzcycgXToKICAgICAgICAgICAgc2VjdXJpdHlfY29uZmlnW3BhcmFtZXRlci5rZX"
"ldID0gcGFyYW1ldGVyLnZhbHVlX3N0cgogICAgZ2xvYmFsX2NvbmZpZy5hcHBseSgpCiAgICBzZ"
"XR0aW5nc19jb25maWcuYXBwbHkoKQogICAgc2VjdXJpdHlfY29uZmlnLmFwcGx5KCkKICAgIG9z"
"LnJlbW92ZSgiJXMvenh0bS9nbG9iYWwuY2ZnIiAlIFpFVVNIT01FKQogICAgb3MucmVuYW1lKAo"
"gICAgICAgICIlcy96eHRtL2NvbmYvenh0bXMvKG5vbmUpIiAlIFpFVVNIT01FLCAKICAgICAgIC"
"AiJXMvenh0bS9jb25mL3p4dG1zLyVzIiAlIChaRVVTSE9NRSwgdXNlcl9kYXRhWydob3N0bmFtZ"
"SddKQogICAgKQogICAgb3Muc3ltbGluaygKICAgICAgICAiJXMvenh0bS9jb25mL3p4dG1zLyVz"
"IiAlIChaRVVTSE9NRSwgdXNlcl9kYXRhWydob3N0bmFtZSddKSwgCiAgICAgICAgIiVzL3p4dG0"
"vZ2xvYmFsLmNmZyIgJSBaRVVTSE9NRQogICAgKQogICAgY2FsbChbICIlcy96eHRtL2Jpbi9zeX"
"Njb25maWciICUgWkVVU0hPTUUsICItLWFwcGx5IiBdKQogICAgY2FsbCgiJXMvc3RhcnQtemV1c"
"yIgJSBaRVVTSE9NRSkKICAgIGlmIG5ld191c2VyIGlzIG5vdCBOb25lOgogICAgICAgIHVzZXJf"
"cHJvYyA9IFBvcGVuKAogICAgICAgICAgICBbIiVzL3p4dG0vYmluL3pjbGkiICUgWkVVU0hPTUV"
"dLAogICAgICAgICAgICBzdGRvdXQ9UElQRSwgc3RkaW49UElQRSwgc3RkZXJyPVNURE9VVAogIC"
"AgICAgICkKICAgICAgICB1c2VyX3Byb2MuY29tbXVuaWNhdGUoaW5wdXQ9IlVzZXJzLmFkZFVzZ"
"XIgJXMsICVzLCAlcyIgJSAoCiAgICAgICAgICAgIG5ld191c2VyWyd1c2VybmFtZSddLCBuZXdf"
"dXNlclsncGFzc3dvcmQnXSwgbmV3X3VzZXJbJ2dyb3VwJ10KICAgICAgICApKVswXQogICAgaWY"
"gdXNlcl9kYXRhWydjbHVzdGVyX2pvaW5fZGF0YSddIGlzIG5vdCBOb25lOgogICAgICAgIHdpdG"
"ggb3BlbigiL3RtcC9yZXBsYXlfZGF0YSIsICJ3IikgYXMgcmVwbGF5X2ZpbGU6CiAgICAgICAgI"
"CAgIHJlcGxheV9maWxlLndyaXRlKHVzZXJfZGF0YVsnY2x1c3Rlcl9qb2luX2RhdGEnXSkKICAg"
"ICAgICBjYWxsKFsgIiVzL3p4dG0vY29uZmlndXJlIiAlIFpFVVNIT01FLCAiLS1yZXBsYXktZnJ"
"vbT0vdG1wL3JlcGxheV9kYXRhIiBdKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgIC"
"BtYWluKCkK"
"""
    path: /root/configure.py

runcmd:
-   [ "python", "/root/configure.py" ]
    """ % base64.b64encode(json.dumps(user_data)))
