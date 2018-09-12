#!/usr/bin/env python

from ..environment import env_data
import pytest
from ..lib.vtm_object_templates import traffic_ip_group


def test_servers_active(assert_functions, loadbalancer):
    assert_functions.assert_server_active(
        "vtm-{}-pri".format(loadbalancer['id'])
    )
    assert_functions.assert_server_active(
        "vtm-{}-sec".format(loadbalancer['id'])
    )


def test_traffic_ip_group(assert_functions, loadbalancer):
    assert_functions.assert_vtm_config(
        "vtm-{}-pri".format(loadbalancer['id']),
        {
            "traffic_ip_groups": [
                traffic_ip_group(
                    loadbalancer['id'],
                    [loadbalancer['vip_address']]
                )
            ]
        }
    )


def test_ports_exist(assert_functions, loadbalancer):
    assert_functions.assert_port_exists(
        "data-vtm-{}-pri".format(loadbalancer['id'])
    )
    assert_functions.assert_port_exists(
        "mgmt-vtm-{}-pri".format(loadbalancer['id'])
    )
    assert_functions.assert_port_exists(
        "data-vtm-{}-sec".format(loadbalancer['id'])
    )
    assert_functions.assert_port_exists(
        "mgmt-vtm-{}-sec".format(loadbalancer['id'])
    )


def test_security_groups(assert_functions, loadbalancer):
    assert_functions.assert_security_group_exists(
        "lbaas-{}".format(loadbalancer['id'])
    )
    assert_functions.assert_security_group_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id'])
    )


def test_allowed_address_pairs(assert_functions, loadbalancer):
    assert_functions.assert_allowed_address_pairs_contains_ip(
        "data-vtm-{}-pri".format(loadbalancer['id']),
        loadbalancer['vip_address']
    ) 
    assert_functions.assert_allowed_address_pairs_contains_ip(
        "data-vtm-{}-sec".format(loadbalancer['id']),
        loadbalancer['vip_address']
    ) 


def test_security_group_rules(assert_functions, loadbalancer):
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 9070
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 9080
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 9080, "udp"
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 9090
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 22
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), 161, "udp"
    )
    assert_functions.assert_security_group_rule_exists(
        "mgmt-lbaas-{}".format(loadbalancer['id']), "all", "icmp"
    )

    assert_functions.assert_security_group_rule_not_exists(
        "lbaas-{}".format(loadbalancer['id']), 9070
    )
    assert_functions.assert_security_group_rule_not_exists(
        "lbaas-{}".format(loadbalancer['id']), 9080
    )
    assert_functions.assert_security_group_rule_not_exists(
        "lbaas-{}".format(loadbalancer['id']), 9080, "udp"
    )
    assert_functions.assert_security_group_rule_not_exists(
        "lbaas-{}".format(loadbalancer['id']), 9090
    )
    assert_functions.assert_security_group_rule_exists(
        "lbaas-{}".format(loadbalancer['id']), "all", "icmp"
    )

def test_service_director_registration(assert_functions, loadbalancer):
    assert_functions.assert_sd_instance_exists(
        "vtm-{}-pri".format(loadbalancer['id'])
    )
    assert_functions.assert_sd_instance_exists(
        "vtm-{}-sec".format(loadbalancer['id'])
    )
    assert_functions.assert_sd_instance_licensed(
        "vtm-{}-pri".format(loadbalancer['id'])
    )
    assert_functions.assert_sd_instance_licensed(
        "vtm-{}-sec".format(loadbalancer['id'])
    )
    assert_functions.assert_sd_instance_bandwidth(
        "vtm-{}-pri".format(loadbalancer['id']), env_data['instance_bandwidth']
    )
    assert_functions.assert_sd_instance_bandwidth(
        "vtm-{}-sec".format(loadbalancer['id']), env_data['instance_bandwidth']
    )
    assert_functions.assert_sd_instance_feature_pack(
        "vtm-{}-pri".format(loadbalancer['id']),
         env_data['instance_feature_pack']
    )
    assert_functions.assert_sd_instance_feature_pack(
        "vtm-{}-sec".format(loadbalancer['id']),
        env_data['instance_feature_pack']
    )
