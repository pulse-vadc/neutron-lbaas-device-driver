#!/usr/bin/env python

from ..environment import env_data
import pytest

if env_data['loadbalancer_id'] is not None:
    pytest.skip(
        "Skipping delete tests on pre-existing loadbalancer",
        allow_module_level=True
    )


@pytest.fixture(scope="module")
def delete_loadbalancer(neutron, loadbalancer):
    neutron.delete_loadbalancer(loadbalancer['id'])
    yield loadbalancer


def test_servers_deleted(assert_functions, delete_loadbalancer):
    assert_functions.assert_server_not_exists(
        "vtm-{}-pri".format(delete_loadbalancer['id'])
    )
    assert_functions.assert_server_not_exists(
        "vtm-{}-sec".format(delete_loadbalancer['id'])
    )


def test_security_groups_deleted(assert_functions, delete_loadbalancer):
    assert_functions.assert_security_group_not_exists(
        "lbaas-{}".format(delete_loadbalancer['id'])
    )
    assert_functions.assert_security_group_not_exists(
        "mgmt-lbaas-{}".format(delete_loadbalancer['id'])
    )


def test_ports_deleted(assert_functions, delete_loadbalancer):
    assert_functions.assert_port_not_exists(
        "data-vtm-{}-pri".format(delete_loadbalancer['id'])
    )
    assert_functions.assert_port_not_exists(
        "mgmt-vtm-{}-pri".format(delete_loadbalancer['id'])
    )
    assert_functions.assert_port_not_exists(
        "data-vtm-{}-sec".format(delete_loadbalancer['id'])
    )
    assert_functions.assert_port_not_exists(
        "mgmt-vtm-{}-sec".format(delete_loadbalancer['id'])
    )
