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
from struct import pack
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
        keystone = self.get_keystone_client()
        neutron_service = keystone.services.find(name="neutron")
        nova_service = keystone.services.find(name="nova")
        if cfg.CONF.lbaas_settings.keystone_version == "2":
            self.neutron_endpoint = keystone.endpoints.find(
                service_id=neutron_service.id
            ).adminurl
            nova_endpoint = keystone.endpoints.find(
                service_id=nova_service.id
            ).adminurl
            self.nova_endpoint = nova_endpoint.replace(
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
                    create_floating_ip=False, security_group=None):
        neutron = self.get_neutron_client()
        if mgmt_port is False:
            subnet = neutron.show_subnet(lb.vip_subnet_id)
            network_id = subnet['subnet']['network_id']
        else:
            network_id = cfg.CONF.lbaas_settings.management_network
        port = neutron.create_port(
            {"port": {
                "admin_state_up": True,
                "network_id": network_id,
                "tenant_id": self.lbaas_project_id,
                "name": "%s-%s" % ("mgmt" if mgmt_port else "data", hostname)
            }}
        )['port']

        if cfg.CONF.lbaas_settings.deployment_model == "PER_LOADBALANCER":
            sec_grp_uuid = lb.id
        elif cfg.CONF.lbaas_settings.deployment_model == "PER_TENANT":
            sec_grp_uuid = lb.tenant_id

        if create_floating_ip is True:
            floatingip = self.create_floatingip(port['id'])
            mgmt_ip = floatingip['floatingip']['floating_ip_address']
            if security_group is None:
                sec_grp = self.create_lb_security_group(
                    sec_grp_uuid, mgmt_port=True, cluster=cluster
                )
                security_group = sec_grp['security_group']['id']
        else:
            if security_group is None:
                if mgmt_port is False:
                    sec_grp = self.create_lb_security_group(sec_grp_uuid)
                else:
                    sec_grp = self.create_lb_security_group(
                        sec_grp_uuid, mgmt_port=True, mgmt_label=True,
                        cluster=cluster
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
        # If GUI access is allowed, open up the GUI port
        if cfg.CONF.vtm_settings.gui_access is True and not mgmt_label:
            self.create_security_group_rule(
                tenant_id,
                sec_grp['security_group']['id'],
                port=cfg.CONF.vtm_settings.admin_port
            )
        # If mgmt_port, add the necessary rules to allow management traffic
        # i.e. allow each Services Director to access the REST port of the
        # instance
        if mgmt_port:
            for server in cfg.CONF.lbaas_settings.configuration_source_ips:
                self.create_security_group_rule(
                    tenant_id,
                    sec_grp['security_group']['id'],
                    port=cfg.CONF.vtm_settings.rest_port,
                    src_addr=socket.gethostbyname(server)
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
        return sec_grp

    def create_security_group_rule(self, tenant_id, sec_grp_id, port,
                                   src_addr=None, remote_group=None,
                                   direction="ingress", protocol='tcp'):
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
            "security_group_id": sec_grp_id,
            "tenant_id": tenant_id
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
        self.create_security_group_rule(
            lb.tenant_id, sec_grp['id'], port, protocol=protocol
        )

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
            LOG.error(_("\nError creating vTM instance: %s" % e))
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

    def get_server_port(self, hostname):
        """
        Gets the Neutron ID of a vTM's data port.
        """
        neutron = self.get_neutron_client()
        server_id = self.get_server_id_from_hostname(hostname)
        ports = neutron.list_ports(device_id=server_id)['ports']
        for port in ports:
            if not port['name'].startswith("mgmt"):
                return port['id']
        raise Exception("No data port found for %s" % hostname)

    def get_server_id_from_hostname(self, hostname):
        """
        Gets the Nova ID of a server from its hostname.
        """
        token = self.get_auth_token()
        response = requests.get(
            "%s/servers" % self.nova_endpoint,
            headers={"X-Auth-Token": token}
        )
        for server in response.json()['servers']:
            if server['name'] == hostname:
                return server['id']
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

    def get_netmask(self, cidr):
        mask = int(cidr.split("/")[1])
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return socket.inet_ntoa(pack('>I', bits))

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
            "appliance!gateway": data_subnet['gateway_ip'],
            "appliance!if!eth0!autoneg": "Yes",
            "appliance!if!eth0!mtu": cfg.CONF.vtm_settings.mtu,
            "appliance!ip!eth0!isexternal": "No",
            "appliance!ssh!port": "2222",
            "rest!bindips": bind_ip,
            "control!bindip": bind_ip if cluster_data else "127.0.0.1",
            "appliance!nameservers":
                " ".join(cfg.CONF.vtm_settings.nameservers)
        }
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
"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uCiNDb3B5cmlnaHQgMjAxNCBCcm9jYWRlIENvbW11bmljYXRpb"
"25zIFN5c3RlbXMsIEluYy4gIEFsbCByaWdodHMgcmVzZXJ2ZWQuCgppbXBvcnQgb3MKaW1wb3J0IG"
"pzb24KZnJvbSBzdWJwcm9jZXNzIGltcG9ydCBQb3BlbiwgUElQRSwgU1RET1VULCBjYWxsCgpjbGF"
"zcyBDb25maWdGaWxlKGRpY3QpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG5hbWUsIHBhdGgpOgog"
"ICAgICAgIHNlbGYuZmlsZW5hbWUgPSAiJXMvJXMiICUgKHBhdGgsIG5hbWUpCiAgICAgICAgc2VsZ"
"i5fZ2V0X2N1cnJlbnRfa2V5cygpCgogICAgZGVmIGFwcGx5KHNlbGYpOgogICAgICAgIHdpdGggb3"
"BlbihzZWxmLmZpbGVuYW1lLCAidyIpIGFzIGNvbmZpZ19maWxlOgogICAgICAgICAgICBmb3Iga2V"
"5LCB2YWx1ZSBpbiBzZWxmLml0ZXJpdGVtcygpOgogICAgICAgICAgICAgICAgY29uZmlnX2ZpbGUu"
"d3JpdGUoIiVzXHQlc1xuIiAlIChrZXksIHZhbHVlKSkKCiAgICBkZWYgX2dldF9jdXJyZW50X2tle"
"XMoc2VsZik6CiAgICAgICAgd2l0aCBvcGVuKHNlbGYuZmlsZW5hbWUpIGFzIGNvbmZpZ19maWxlOg"
"ogICAgICAgICAgICBmb3IgbGluZSBpbiBjb25maWdfZmlsZToKICAgICAgICAgICAgICAgIHRyeTo"
"KICAgICAgICAgICAgICAgICAgICBiaXRzID0gbGluZS5zcGxpdCgpCiAgICAgICAgICAgICAgICAg"
"ICAgc2VsZltiaXRzWzBdXSA9ICIgIi5qb2luKGJpdHNbMTpdKQogICAgICAgICAgICAgICAgZXhjZ"
"XB0OgogICAgICAgICAgICAgICAgICAgIHBhc3MKICAgICAgICAKCmNsYXNzIFJlcGxheURhdGEoZG"
"ljdCk6CiAgICBjbGFzcyBSZXBsYXlEYXRhUGFyYW1ldGVyKG9iamVjdCk6CiAgICAgICAgZGVmIF9"
"faW5pdF9fKHNlbGYsIHRleHQpOgogICAgICAgICAgICB3b3JkcyA9IHRleHQuc3RyaXAoKS5zcGxp"
"dCgpCiAgICAgICAgICAgIHNlbGYua2V5ID0gd29yZHNbMF0KICAgICAgICAgICAgc2VsZi5wcmVma"
"XggPSB3b3Jkc1swXS5zcGxpdCgiISIpWzBdCiAgICAgICAgICAgIHNlbGYudmFsdWVfbGlzdCA9IH"
"dvcmRzWzE6XQogICAgICAgICAgICBzZWxmLnZhbHVlX3N0ciA9ICIgIi5qb2luKHdvcmRzWzE6XSk"
"KCiAgICBkZWYgX19pbml0X18oc2VsZiwgdGV4dCk6CiAgICAgICAgZm9yIGxpbmUgaW4gdGV4dC5z"
"cGxpdCgiXG4iKToKICAgICAgICAgICAgd29yZHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICAgICAgd"
"HJ5OgogICAgICAgICAgICAgICAgc2VsZlt3b3Jkc1swXV0gPSBzZWxmLlJlcGxheURhdGFQYXJhbW"
"V0ZXIobGluZSkKICAgICAgICAgICAgZXhjZXB0IEluZGV4RXJyb3I6CiAgICAgICAgICAgICAgICB"
"wYXNzCiAgICAgICAgCgpkZWYgbWFpbigpOgogICAgWkVVU0hPTUUgPSBvcy5lbnZpcm9uLmdldCgn"
"WkVVU0hPTUUnLCAnL29wdC96ZXVzJykKICAgIG5ld191c2VyID0gTm9uZQogICAgdXVpZF9nZW5lc"
"mF0ZV9wcm9jID0gUG9wZW4oCiAgICAgICAgWyIlcy96eHRtL2Jpbi96Y2xpIiAlIFpFVVNIT01FXS"
"wKICAgICAgICBzdGRvdXQ9UElQRSwgc3RkaW49UElQRSwgc3RkZXJyPVNURE9VVAogICAgKQogICA"
"gdXVpZF9nZW5lcmF0ZV9wcm9jLmNvbW11bmljYXRlKGlucHV0PSJTeXN0ZW0uTWFuYWdlbWVudC5y"
"ZWdlbmVyYXRlVVVJRCIpWzBdCiAgICBjYWxsKCIlcy9zdG9wLXpldXMiICUgWkVVU0hPTUUpCiAgI"
"CB3aXRoIG9wZW4oIi9yb290L2NvbmZpZ19kYXRhIikgYXMgY29uZmlnX2RyaXZlOgogICAgICAgIH"
"VzZXJfZGF0YSA9IGpzb24ubG9hZHMoY29uZmlnX2RyaXZlLnJlYWQoKSkKICAgIGdsb2JhbF9jb25"
"maWcgPSBDb25maWdGaWxlKCdnbG9iYWwuY2ZnJywgIiVzL3p4dG0iICUgWkVVU0hPTUUpCiAgICBz"
"ZXR0aW5nc19jb25maWcgPSBDb25maWdGaWxlKCdzZXR0aW5ncy5jZmcnLCAiJXMvenh0bS9jb25mI"
"iAlIFpFVVNIT01FKQogICAgc2VjdXJpdHlfY29uZmlnID0gQ29uZmlnRmlsZSgnc2VjdXJpdHknLC"
"AiJXMvenh0bS9jb25mIiAlIFpFVVNIT01FKQogICAgcmVwbGF5X2RhdGEgPSBSZXBsYXlEYXRhKHV"
"zZXJfZGF0YVsncmVwbGF5X2RhdGEnXSkKICAgIGZvciBwYXJhbWV0ZXIgaW4gcmVwbGF5X2RhdGEu"
"dmFsdWVzKCk6CiAgICAgICAgaWYgcGFyYW1ldGVyLmtleSA9PSAiYWRtaW4hcGFzc3dvcmQiOgogI"
"CAgICAgICAgICBwYXNzd29yZF9wcm9jID0gUG9wZW4oCiAgICAgICAgICAgICAgICBbJ3otcmVzZX"
"QtcGFzc3dvcmQnXSwgCiAgICAgICAgICAgICAgICBzdGRvdXQ9UElQRSwgc3RkaW49UElQRSwgc3R"
"kZXJyPVNURE9VVAogICAgICAgICAgICApCiAgICAgICAgICAgIHN0ZG91dCA9IHBhc3N3b3JkX3By"
"b2MuY29tbXVuaWNhdGUoaW5wdXQ9IiVzXG4lcyIgJSAoCiAgICAgICAgICAgICAgICBwYXJhbWV0Z"
"XIudmFsdWVfc3RyLCBwYXJhbWV0ZXIudmFsdWVfc3RyCiAgICAgICAgICAgICkpWzBdCiAgICAgIC"
"AgZWxpZiBwYXJhbWV0ZXIua2V5ID09ICJtb25pdG9yX3VzZXIiOgogICAgICAgICAgICBuZXdfdXN"
"lciA9IHsgCiAgICAgICAgICAgICAgICAidXNlcm5hbWUiOiBwYXJhbWV0ZXIudmFsdWVfbGlzdFsw"
"XSwKICAgICAgICAgICAgICAgICJwYXNzd29yZCI6IHBhcmFtZXRlci52YWx1ZV9saXN0WzFdLAogI"
"CAgICAgICAgICAgICAgImdyb3VwIjogIkd1ZXN0IgogICAgICAgICAgICB9CiAgICAgICAgZWxpZi"
"BwYXJhbWV0ZXIua2V5IGluIFsgJ3Jlc3QhZW5hYmxlZCcsICdjb250cm9sYWxsb3cnIF06CiAgICA"
"gICAgICAgIHNldHRpbmdzX2NvbmZpZ1twYXJhbWV0ZXIua2V5XSA9IHBhcmFtZXRlci52YWx1ZV9z"
"dHIKICAgICAgICBlbGlmIHBhcmFtZXRlci5rZXkgaW4gWyAnZGV2ZWxvcGVyX21vZGVfYWNjZXB0Z"
"WQnLCAnbmFtZWlwJyBdOgogICAgICAgICAgICBnbG9iYWxfY29uZmlnW3BhcmFtZXRlci5rZXldID"
"0gcGFyYW1ldGVyLnZhbHVlX3N0cgogICAgICAgIGVsaWYgcGFyYW1ldGVyLnByZWZpeCBpbiBbICd"
"hcHBsaWFuY2UnLCAncmVzdCcsICdjb250cm9sJyBdOgogICAgICAgICAgICBnbG9iYWxfY29uZmln"
"W3BhcmFtZXRlci5rZXldID0gcGFyYW1ldGVyLnZhbHVlX3N0cgogICAgICAgIGVsaWYgcGFyYW1ld"
"GVyLmtleSBpbiBbICdhY2Nlc3MnIF06CiAgICAgICAgICAgIHNlY3VyaXR5X2NvbmZpZ1twYXJhbW"
"V0ZXIua2V5XSA9IHBhcmFtZXRlci52YWx1ZV9zdHIKICAgIGdsb2JhbF9jb25maWcuYXBwbHkoKQo"
"gICAgc2V0dGluZ3NfY29uZmlnLmFwcGx5KCkKICAgIHNlY3VyaXR5X2NvbmZpZy5hcHBseSgpCiAg"
"ICBvcy5yZW1vdmUoIiVzL3p4dG0vZ2xvYmFsLmNmZyIgJSBaRVVTSE9NRSkKICAgIG9zLnJlbmFtZ"
"SgKICAgICAgICAiJXMvenh0bS9jb25mL3p4dG1zLyhub25lKSIgJSBaRVVTSE9NRSwgCiAgICAgIC"
"AgIiVzL3p4dG0vY29uZi96eHRtcy8lcyIgJSAoWkVVU0hPTUUsIHVzZXJfZGF0YVsnaG9zdG5hbWU"
"nXSkKICAgICkKICAgIG9zLnN5bWxpbmsoCiAgICAgICAgIiVzL3p4dG0vY29uZi96eHRtcy8lcyIg"
"JSAoWkVVU0hPTUUsIHVzZXJfZGF0YVsnaG9zdG5hbWUnXSksIAogICAgICAgICIlcy96eHRtL2dsb"
"2JhbC5jZmciICUgWkVVU0hPTUUKICAgICkKICAgIGNhbGwoWyAiJXMvenh0bS9iaW4vc3lzY29uZm"
"lnIiAlIFpFVVNIT01FLCAiLS1hcHBseSIgXSkKICAgIGNhbGwoIiVzL3N0YXJ0LXpldXMiICUgWkV"
"VU0hPTUUpCiAgICBpZiBuZXdfdXNlciBpcyBub3QgTm9uZToKICAgICAgICB1c2VyX3Byb2MgPSBQ"
"b3BlbigKICAgICAgICAgICAgWyIlcy96eHRtL2Jpbi96Y2xpIiAlIFpFVVNIT01FXSwKICAgICAgI"
"CAgICAgc3Rkb3V0PVBJUEUsIHN0ZGluPVBJUEUsIHN0ZGVycj1TVERPVVQKICAgICAgICApCiAgIC"
"AgICAgdXNlcl9wcm9jLmNvbW11bmljYXRlKGlucHV0PSJVc2Vycy5hZGRVc2VyICVzLCAlcywgJXM"
"iICUgKAogICAgICAgICAgICBuZXdfdXNlclsndXNlcm5hbWUnXSwgbmV3X3VzZXJbJ3Bhc3N3b3Jk"
"J10sIG5ld191c2VyWydncm91cCddCiAgICAgICAgKSlbMF0KICAgIGlmIHVzZXJfZGF0YVsnY2x1c"
"3Rlcl9qb2luX2RhdGEnXSBpcyBub3QgTm9uZToKICAgICAgICB3aXRoIG9wZW4oIi90bXAvcmVwbG"
"F5X2RhdGEiLCAidyIpIGFzIHJlcGxheV9maWxlOgogICAgICAgICAgICByZXBsYXlfZmlsZS53cml"
"0ZSh1c2VyX2RhdGFbJ2NsdXN0ZXJfam9pbl9kYXRhJ10pCiAgICAgICAgY2FsbChbICIlcy96eHRt"
"L2NvbmZpZ3VyZSIgJSBaRVVTSE9NRSwgIi0tcmVwbGF5LWZyb209L3RtcC9yZXBsYXlfZGF0YSIgX"
"SkKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgbWFpbigpCg=="
"""
    path: /root/configure.py

runcmd:
-   [ "python", "/root/configure.py" ]
    """ % base64.b64encode(json.dumps(user_data)))
