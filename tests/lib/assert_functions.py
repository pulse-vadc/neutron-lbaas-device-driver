#!/usr/bin/env python

import base64
from connectors import ServicesDirector, Keystone, Barbican, Neutron, Nova
import hashlib
from keystoneclient.v3 import client as keystone_client
from neutronclient.neutron import client as neutron_client
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import vtm_object_templates

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AssertFunctions(object):
    def __init__(self, env_data):
        lbaas_keystone = Keystone(
            env_data['keystone_url'],
            env_data['lbaas_username'],
            env_data['lbaas_project_id'],
            env_data['lbaas_password']
        )
        test_user_keystone = Keystone(
            env_data['keystone_url'],
            env_data['test_user_username'],
            env_data['test_user_project_id'],
            env_data['test_user_password']
        )
        self.sd = ServicesDirector(
            env_data['services_director_url'],
            env_data['services_director_username'],
            env_data['services_director_password']
        )
        self.lbaas_neutron = Neutron(env_data['neutron_url'], lbaas_keystone)
        self.lbaas_nova = Nova(env_data['nova_url'], lbaas_keystone)
        self.test_user_neutron = Neutron(env_data['neutron_url'], test_user_keystone)
        self.test_user_nova = Nova(env_data['nova_url'], test_user_keystone)
        self.barbican = Barbican(
            env_data['barbican_url'],
            env_data['test_user_project_id']
        )

    def assert_vtm_config(self, instance_id, expected_config):
        for obj_type, obj_list in expected_config.iteritems():
            for obj in obj_list:
                actual_config = self.sd.get_instance_config(
                    instance_id, obj_type, obj['name']
                )
                if actual_config is None:
                    raise Exception(
                        "assert_vtm_config failed: {} '{}' does not exist."
                        .format(obj_type, obj['name'])
                    )
                try:
                    self._assert_configs_match(obj['config'], actual_config)
                except Exception as e:
                    raise Exception(
                        "assert_vtm_config failed: {} '{}' {}"
                        .format(obj_type, obj['name'], e)
                    )

    def assert_vtm_object_deleted(self, instance_id, obj_type, obj_name):
        obj = self.sd.get_instance_config(instance_id, obj_type, obj_name)
        if obj is not None:
            raise Exception(
                "assert_vtm_object_deleted failed: {} '{}' exists."
                .format(obj_type, obj_name)
            )

    def assert_sd_instance_exists(self, instance_id):
        instance = self.sd.get_instance(instance_id)
        if instance is None:
            raise Exception(
                "assert_sd_instance_exists failed: instance {} does not exist."
                .format(instance_id)
            )

    def assert_sd_instance_licensed(self, instance_id):
        instance = self.sd.get_instance(instance_id)
        if instance is None:
            raise Exception(
                "assert_sd_instance_licensed failed: instance {} does "
                "not exist.".format(instance_id)
            )
        try:
            if instance['licensed_date'] == "":
                raise KeyError("licensed_date")
        except KeyError:
            raise Exception(
                "assert_sd_instance_licensed failed: instance {} is not "
                "licensed.".format(instance_id)
            )

    def assert_sd_instance_bandwidth(self, instance_id, expected_bandwidth):
        instance = self.sd.get_instance(instance_id)
        if instance is None:
            raise Exception(
                "assert_sd_instance_bandwidth failed: instance {} does "
                "not exist.".format(instance_id)
            )
        if instance['bandwidth'] != expected_bandwidth:
            raise Exception(
                "assert_sd_instance_bandwidth failed: instance {} has "
                "bandwidth {}, expected {}."
                .format(instance_id, instance['bandwidth'], expected_bandwidth)
            )

    def assert_sd_instance_feature_pack(self, instance_id, expected_fp):
        instance = self.sd.get_instance(instance_id)
        if instance is None:
            raise Exception(
                "assert_sd_instance_feature_pack failed: instance {} does "
                "not exist.".format(instance_id)
            )
        if instance['stm_feature_pack'] != expected_fp:
            raise Exception(
                "assert_sd_instance_feature_pack failed: instance {} has "
                "feature_pack '{}', expected '{}'."
                .format(instance_id, instance['feature_pack'], expected_fp)
            )

    def assert_server_active(self, server):
        server = self.lbaas_nova.get_server(server)
        if server is None:
            raise Exception(
                "assert_server_active failed: server {} does not exist."
                .format(server)
            )
        if server['status'] != "ACTIVE":
            raise Exception(
                "assert_server_active failed: server {} in {} state."
                .format(server, server['status'])
            )

    def assert_server_not_exists(self, server):
        try:
            server = self.lbaas_nova.get_server(server)
        except IndexError:
            return
        raise Exception(
            "assert_server_not_exists failed: server {} does exist."
            .format(server)
        )

    def assert_security_group_exists(self, name):
        try:
            self._get_security_group(name)
        except IndexError:
            raise Exception(
                "assert_security_group_exists failed: security group {} does "
                "not exist.".format(name)
            )

    def assert_security_group_not_exists(self, name):
        try:
            self._get_security_group(name)
        except IndexError:
            return
        raise Exception(
            "assert_security_group_not_exists failed: security group {} does "
            "exist.".format(name)
        )

    def assert_security_group_rule_exists(
        self, name, port, protocol="tcp"
    ):
        sec_grp = self._get_security_group(name)
        for rule in sec_grp['security_group']['security_group_rules']:
            if rule['protocol'] == "icmp" and protocol == "icmp":
                return
            if(( rule['port_range_min'] <= port <=rule['port_range_max'])
            and  rule['protocol'] == protocol):
                return
        raise Exception(
            "assert_security_group_rule_exists failed: security group {} "
            "does not contain a rule for {} port {}."
            .format(name, protocol, port)
        )

    def assert_security_group_rule_not_exists(
        self, name, port, protocol="tcp"
    ):
        try:
            self.assert_security_group_rule_exists(name, port, protocol)
        except:
            return
        raise Exception(
            "assert_security_group_rule_not_exists failed: security group {} "
            "does contain a rule for {} port {}."
            .format(name, protocol, port)
        )

    def assert_port_exists(self, name):
        port_list = self.lbaas_neutron.list_ports(name=name)
        try:
            port = port_list['ports'][0]
        except IndexError:
            raise Exception(
                "assert_port_exists failed: port {} does not exist."
                .format(name)
            )

    def assert_port_not_exists(self, name):
        port_list = self.lbaas_neutron.list_ports(name=name)
        try:
            port = port_list['ports'][0]
        except IndexError:
            return
        raise Exception(
            "assert_port_not_exists failed: port {} does exist.".format(name)
        )

    def assert_allowed_address_pairs_contains_ip(self, name, ip_address):
        port_list = self.lbaas_neutron.list_ports(name=name)
        port = port_list['ports'][0]
        for pair in port['allowed_address_pairs']:
            if pair['ip_address'] == ip_address:
                return
        raise Exception(
            "assert_allowed_address_pairs_contains_ip failed: port {} does "
            "not contain '{}' in the allowed_address_pairs list."
            .format(port['id'], ip_address)
        )

    def assert_certificates_match(self, instance_id, listener_id, container_id):
        vtm_cert_name = "{}-{}".format(listener_id, container_id)
        vtm_certs = self.sd.get_instance_config(
            instance_id, "ssl/server_keys", vtm_cert_name
        )
        if vtm_certs is None:
            raise Exception(
                "assert_certificates_match failed: server_key '{}-{}' does "
                "not exist on vTM.".format(listener_id, container_id)
            )
        vtm_public_key = vtm_certs['properties']['basic']['public']
        barbican_public_key = self.barbican.get_public_key(container_id)
        if vtm_public_key != barbican_public_key:
            raise Exception(
                "assert_certificates_match failed: the public key of "
                "server_key '{0}-{1}' does not match the public key in "
                "Barbican container {1}.".format(listener_id, container_id)
            )
        vtm_private_key_signature = vtm_certs['properties']['basic']['private']
        barbican_private_key = self.barbican.get_private_key_signature(container_id)
        if vtm_private_key_signature != barbican_private_key:
            raise Exception(
                "assert_certificates_match failed: the signature of the "
                "private key server_key '{0}-{1}' does not match the "
                "signature of the private key in Barbican container {1}."
                .format(listener_id, container_id)
            )

    def assert_member_status_active(self, member_id, pool_id):
        self._assert_member_status(member_id, pool_id, "active")

    def assert_member_status_inactive(self, member_id, pool_id):
        self._assert_member_status(member_id, pool_id, "inactive")

    def _assert_member_status(self, member_id, pool_id, status):
        member = self.test_user_neutron.show_lbaas_member(member_id, pool_id)
        if member['member']['member_status'] != status.upper():
            raise Exception(
                "assert_node_{} failed: got member_status '{}'"
                .format(status, member['member']['member_status'])
            )

    def _assert_configs_match(self, expected, actual):
        for section, fields in expected['properties'].iteritems():
            for field_name, field_value in fields.iteritems():
                try:
                    real_value = actual['properties'][section][field_name]
                except KeyError:
                    raise Exception(
                        "field {}->{} not found.".format(section, field_name)
                    )
                if field_value != real_value:
                    raise Exception("expected {}->{}='{}', got '{}'.".format(
                        section, field_name, field_value, real_value
                    ))

    def _get_security_group(self, name):
        sec_grps = self.lbaas_neutron.list_security_groups(name=name)
        sec_grp_id = sec_grps['security_groups'][0]['id']
        sec_grp = self.lbaas_neutron.show_security_group(sec_grp_id)
        return sec_grp
